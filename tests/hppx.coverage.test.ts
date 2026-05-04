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

    describe("assignment fallback when defineProperty fails", () => {
      // Synchronously install/restore the Object.defineProperty patch via
      // beforeEach/afterEach instead of setTimeout(..., 0). The previous
      // setTimeout-based restore was racy: if the next test started before the
      // macrotask fired (e.g. under load or when --testTimeout shifts macrotask
      // ordering), Object.defineProperty was still broken and unrelated tests
      // would fail intermittently.
      const originalDefineProperty = Object.defineProperty;
      let targetReq: any = null;
      let callCount = 0;

      beforeEach(() => {
        targetReq = null;
        callCount = 0;
        Object.defineProperty = function <T>(
          obj: T,
          prop: PropertyKey,
          descriptor: PropertyDescriptor & ThisType<any>,
        ): T {
          // Fail the first few defineProperty calls on the targeted req to
          // force fallback to direct assignment.
          if (
            obj === targetReq &&
            (prop === "queryPolluted" || prop === "bodyPolluted") &&
            callCount < 2
          ) {
            callCount++;
            throw new Error("defineProperty blocked");
          }
          return originalDefineProperty.call(Object, obj, prop, descriptor) as T;
        };
      });

      afterEach(() => {
        Object.defineProperty = originalDefineProperty;
      });

      test("falls back to direct assignment when defineProperty throws", async () => {
        const app = express();

        // Capture the per-request `req` reference so the patched defineProperty
        // only sabotages calls targeting it (avoids breaking unrelated
        // defineProperty calls inside Express internals).
        app.use((req: any, _res, next) => {
          targetReq = req;
          next();
        });

        app.use(hppx({ logPollution: false }));

        app.get("/test", (req, res) => {
          // queryPolluted should be set via fallback assignment after
          // defineProperty throws.
          res.json({
            hasQueryPolluted: typeof req.queryPolluted !== "undefined",
            queryPolluted: req.queryPolluted ?? null,
            query: req.query,
          });
        });

        const res = await request(app).get("/test?a=1&a=2");
        expect(res.status).toBe(200);
        // Strengthened assertions: confirm sanitization actually happened via
        // the fallback path (req.query reduced to "2") AND the polluted tree
        // captured the original array — not just "no crash".
        expect(res.body.hasQueryPolluted).toBe(true);
        expect(res.body.query).toEqual({ a: "2" });
        expect(res.body.queryPolluted).toEqual({ a: ["1", "2"] });
      });
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

    afterEach(() => {
      process.env.NODE_ENV = originalEnv;
      // console.error/warn spies installed via jest.spyOn are auto-restored by
      // Jest's `restoreMocks: true` (jest.config.ts).
    });

    test("falls back to console.error when logger fails in development", async () => {
      process.env.NODE_ENV = "development";

      // Use jest.spyOn(console, 'error') with mockImplementation(() => {}) so
      // the test does not leak "[hppx] Logger failed" lines to stderr (which
      // is otherwise visible in CI output and confuses developers running the
      // suite locally). Auto-restored by `restoreMocks: true`.
      const consoleErrorSpy = jest.spyOn(console, "error").mockImplementation(() => {});

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
      const calls = consoleErrorSpy.mock.calls;
      expect(calls.length).toBeGreaterThan(0);
      expect(
        calls.some((args) =>
          args.some((arg: any) => typeof arg === "string" && arg.includes("[hppx]")),
        ),
      ).toBe(true);
    });

    test("falls back to console.error regardless of NODE_ENV (production)", async () => {
      // The dev/prod gate was removed: a logger failure is a developer bug that
      // should be surfaced to console.error regardless of NODE_ENV. Also, the
      // previous gate referenced `process.env` directly which crashes on edge
      // runtimes where `process` is undefined.
      process.env.NODE_ENV = "production";

      const consoleErrorSpy = jest.spyOn(console, "error").mockImplementation(() => {});

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

      // Console.error MUST have been called even in production (logger failure
      // is a developer bug they should always know about).
      const hppxErrors = consoleErrorSpy.mock.calls.filter((args) =>
        args.some((arg: any) => typeof arg === "string" && arg.includes("[hppx]")),
      );
      expect(hppxErrors.length).toBeGreaterThan(0);
    });

    test("handles logger that throws during error processing", async () => {
      // Suppress console.error via jest.spyOn so no "[hppx] Logger failed"
      // line leaks to stderr. Auto-restored by `restoreMocks: true`.
      jest.spyOn(console, "error").mockImplementation(() => {});

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

    test("handles truly frozen request properties (graceful warn + polluted tree)", async () => {
      const app = express();

      // Pre-load a frozen, non-configurable + non-writable `req.query` whose
      // value still contains pollution (an array). hppx must:
      //   1. detect the pollution (`queryPolluted.x === ["1","2"]`),
      //   2. attempt to write the sanitized clone back via setReqPropertySafe,
      //   3. surface a warning via the configured logger when the descriptor
      //      forbids the write (non-configurable AND non-writable),
      //   4. NOT crash the request — `next()` is called.
      // The original (still-polluted) value remains observable on req.query;
      // this is the documented graceful-fallback behavior. Asserting it here
      // ensures we don't silently regress to the pre-fix "no warning, no
      // queryPolluted" state.
      const polluted = Object.freeze({ x: ["1", "2"] });
      app.use((req: any, _res, next) => {
        try {
          Object.defineProperty(req, "query", {
            value: polluted,
            writable: false,
            configurable: false,
          });
        } catch (_e) {
          // If the host environment refuses (e.g. a future Express version),
          // skip the test rather than producing a misleading pass.
        }
        next();
      });

      const loggerCalls: string[] = [];
      app.use(
        hppx({
          logPollution: false,
          logger: (entry) => {
            if (typeof entry === "string") loggerCalls.push(entry);
          },
        }),
      );

      app.get("/test", (req, res) => {
        res.json({
          query: req.query,
          queryPolluted: (req as any).queryPolluted ?? null,
        });
      });

      const res = await request(app).get("/test?ignored=1");
      expect(res.status).toBe(200);
      // The polluted tree must still be populated even though the cleaned
      // value could not be written back (security signal preserved).
      expect(res.body.queryPolluted).toEqual({ x: ["1", "2"] });
      // The original frozen, polluted value is still observable on req.query
      // — that is the documented graceful-fallback behavior.
      expect(res.body.query).toEqual({ x: ["1", "2"] });
      // A warning was surfaced through the configured logger so the upstream
      // bug (frozen req.query) stays visible to the developer.
      const warned = loggerCalls.find((m) =>
        m.includes("Could not write sanitized value to req.query"),
      );
      expect(warned).toBeDefined();
    });

    test("frozen request properties fall back to console.warn when no logger is configured", async () => {
      // Mirrors the previous test but omits `logger`, so the warn helper takes
      // the no-logger branch and writes directly to console.warn. We spy on
      // console.warn to assert the path without leaking output.
      const consoleWarnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});

      const app = express();
      const polluted = Object.freeze({ x: ["1", "2"] });
      app.use((req: any, _res, next) => {
        try {
          Object.defineProperty(req, "query", {
            value: polluted,
            writable: false,
            configurable: false,
          });
        } catch (_e) {
          // skip if host refuses
        }
        next();
      });

      app.use(hppx({ logPollution: false }));

      app.get("/test", (req, res) => {
        res.json({
          query: req.query,
          queryPolluted: (req as any).queryPolluted ?? null,
        });
      });

      const res = await request(app).get("/test?ignored=1");
      expect(res.status).toBe(200);
      expect(res.body.queryPolluted).toEqual({ x: ["1", "2"] });
      expect(res.body.query).toEqual({ x: ["1", "2"] });
      // console.warn should have been used as the fallback signal.
      const warnCall = consoleWarnSpy.mock.calls.find((args) =>
        args.some(
          (arg: any) =>
            typeof arg === "string" && arg.includes("Could not write sanitized value to req.query"),
        ),
      );
      expect(warnCall).toBeDefined();
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

  describe("req.path getter throws (defensive read)", () => {
    test("does not propagate errors when req.path getter throws; sanitization still runs", () => {
      // Build a mock req where reading `path` throws synchronously. The
      // middleware must catch the error, treat path as unknown (no exclusion
      // match), proceed to sanitize, and call next() WITHOUT an error
      // argument — i.e. no 500 propagated to the client.
      // Silence the fallback console.warn so the expected "[hppx] Failed to
      // read req.path..." message does not leak to the test runner's stderr.
      // restoreMocks: true (jest.config.ts) auto-restores after the test.
      jest.spyOn(console, "warn").mockImplementation(() => {});
      const middleware = hppx({ excludePaths: ["/skip"], logPollution: false });
      const req: any = {
        query: { x: ["1", "2"] },
        headers: {},
      };
      Object.defineProperty(req, "path", {
        get() {
          throw new Error("boom from req.path getter");
        },
        configurable: true,
      });
      const res: any = {};
      let nextErr: unknown = "uncalled";
      const next = (err?: unknown) => {
        nextErr = err;
      };

      middleware(req, res, next);

      // next() called without an error argument — the path-getter throw was
      // contained, NOT propagated as a 500.
      expect(nextErr).toBeUndefined();
      // Sanitization still ran: req.query was reduced (keepLast strategy by default).
      expect(req.query).toEqual({ x: "2" });
      // Pollution was recorded.
      expect(req.queryPolluted).toEqual({ x: ["1", "2"] });
    });

    test("logs req.path getter failure via the configured logger", () => {
      const loggerCalls: unknown[] = [];
      const middleware = hppx({
        excludePaths: ["/skip"],
        logPollution: false,
        logger: (msg) => loggerCalls.push(msg),
      });
      const req: any = { query: {}, headers: {} };
      Object.defineProperty(req, "path", {
        get() {
          throw new Error("path getter blew up");
        },
        configurable: true,
      });
      const res: any = {};
      let nextErr: unknown = "uncalled";
      const next = (err?: unknown) => {
        nextErr = err;
      };

      middleware(req, res, next);

      expect(nextErr).toBeUndefined();
      // The configured logger received a string warning describing the failure.
      const matched = loggerCalls.find(
        (entry) => typeof entry === "string" && entry.includes("Failed to read req.path"),
      );
      expect(matched).toBeDefined();
    });

    test("falls back to console.warn when no logger is configured", () => {
      // Use jest.spyOn(...).mockImplementation so restoreMocks: true
      // automatically tears down the spy between tests, preventing the
      // expected "[hppx] Failed to read req.path..." message from leaking
      // to stderr if the test runner's reporter happens to flush mid-run.
      const warnings: unknown[][] = [];
      const warnSpy = jest.spyOn(console, "warn").mockImplementation((...args: unknown[]) => {
        warnings.push(args);
      });
      const middleware = hppx({ excludePaths: ["/skip"], logPollution: false });
      const req: any = { query: {}, headers: {} };
      Object.defineProperty(req, "path", {
        get() {
          throw new Error("no-logger path-getter failure");
        },
        configurable: true,
      });
      const res: any = {};
      let nextErr: unknown = "uncalled";
      const next = (err?: unknown) => {
        nextErr = err;
      };

      middleware(req, res, next);

      expect(nextErr).toBeUndefined();
      expect(warnSpy).toHaveBeenCalled();
      const matched = warnings.find((args) =>
        args.some((a) => typeof a === "string" && a.includes("Failed to read req.path")),
      );
      expect(matched).toBeDefined();
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

  describe("setReqPropertySafe writable but non-configurable property", () => {
    test("uses direct assignment when target descriptor is writable: true, configurable: false", () => {
      // Pre-install a non-configurable but WRITABLE descriptor for `query` on a
      // mock req. setReqPropertySafe must take the `desc.writable` branch and
      // assign via `target[key] = value` rather than calling defineProperty
      // (which would throw because configurable: false).
      const middleware = hppx({ logPollution: false });
      const req: any = { headers: {} };
      const initial = { x: ["1", "2"] };
      Object.defineProperty(req, "query", {
        value: initial,
        writable: true,
        configurable: false,
        enumerable: true,
      });
      const res: any = {};
      let nextErr: unknown = "uncalled";
      const next = (err?: unknown) => {
        nextErr = err;
      };

      middleware(req, res, next);

      // No error propagated.
      expect(nextErr).toBeUndefined();
      // The cleaned value was written via direct assignment (writable branch).
      expect(req.query).toEqual({ x: "2" });
      // Pollution captured on the polluted tree.
      expect(req.queryPolluted).toEqual({ x: ["1", "2"] });
    });
  });

  describe("Logger fallback paths via console.warn", () => {
    test("path-getter handler falls back to console.warn when configured logger throws", () => {
      // Cover the inner catch in the req.path getter handler: when a logger is
      // configured AND the logger throws, hppx must surface the warning via
      // console.warn so the failure is not silenced.
      const warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
      const throwingLogger = () => {
        throw new Error("logger boom");
      };
      const middleware = hppx({
        excludePaths: ["/skip"],
        logPollution: false,
        logger: throwingLogger,
      });
      const req: any = { query: {}, headers: {} };
      Object.defineProperty(req, "path", {
        get() {
          throw new Error("path getter blew up");
        },
        configurable: true,
      });
      const res: any = {};
      let nextErr: unknown = "uncalled";
      const next = (err?: unknown) => {
        nextErr = err;
      };

      middleware(req, res, next);

      expect(nextErr).toBeUndefined();
      const matched = warnSpy.mock.calls.find((args) =>
        args.some((arg: any) => typeof arg === "string" && arg.includes("Failed to read req.path")),
      );
      expect(matched).toBeDefined();
    });

    test("setReqPropertySafe-failure warn helper falls back to console.warn when logger throws", async () => {
      // Cover the inner catch in the per-request `warn` helper: a frozen
      // req.query forces setReqPropertySafe to call onFailure (the warn
      // helper). With a throwing logger configured, the helper must fall
      // through to console.warn.
      const warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
      const throwingLogger = () => {
        throw new Error("logger boom");
      };
      const app = express();
      const polluted = Object.freeze({ x: ["1", "2"] });
      app.use((req: any, _res, next) => {
        try {
          Object.defineProperty(req, "query", {
            value: polluted,
            writable: false,
            configurable: false,
          });
        } catch (_e) {
          // host refuses; test will still pass on the spy not being called,
          // but on supported runtimes (Node) the descriptor sticks.
        }
        next();
      });
      app.use(hppx({ logPollution: false, logger: throwingLogger }));
      app.get("/test", (req, res) =>
        res.json({
          query: req.query,
          queryPolluted: (req as any).queryPolluted ?? null,
        }),
      );

      const res = await request(app).get("/test?ignored=1");
      expect(res.status).toBe(200);
      // The throwing logger should NOT have prevented the warning; console.warn
      // must have received the same message as a fallback signal.
      const matched = warnSpy.mock.calls.find((args) =>
        args.some(
          (arg: any) =>
            typeof arg === "string" && arg.includes("Could not write sanitized value to req.query"),
        ),
      );
      expect(matched).toBeDefined();
    });
  });

  describe("__hppxProcessed_* flag — defineProperty failure fallback", () => {
    test("falls back to direct assignment when defineProperty throws on the processed flag", () => {
      // Patch Object.defineProperty so the call that defines
      // `__hppxProcessed_query` (with writable: false, configurable: false)
      // throws. The middleware must fall back to plain assignment so the flag
      // is at least set on the current request, preserving multi-middleware
      // skip behavior.
      const originalDefineProperty = Object.defineProperty;
      let targetReq: any = null;
      try {
        const middleware = hppx({ logPollution: false });
        const req: any = { query: { x: ["1", "2"] }, headers: {} };
        targetReq = req;

        Object.defineProperty = function <T>(
          obj: T,
          prop: PropertyKey,
          descriptor: PropertyDescriptor & ThisType<any>,
        ): T {
          if (
            obj === targetReq &&
            typeof prop === "string" &&
            prop.startsWith("__hppxProcessed_")
          ) {
            throw new Error("defineProperty blocked for processed flag");
          }
          return originalDefineProperty.call(Object, obj, prop, descriptor) as T;
        };

        const res: any = {};
        let nextErr: unknown = "uncalled";
        const next = (err?: unknown) => {
          nextErr = err;
        };

        middleware(req, res, next);

        expect(nextErr).toBeUndefined();
        // Sanitization still ran.
        expect(req.query).toEqual({ x: "2" });
        // The processed flag was set via the assignment fallback path so a
        // subsequent middleware would see it.
        expect(req.__hppxProcessed_query).toBe(true);
      } finally {
        Object.defineProperty = originalDefineProperty;
      }
    });
  });

  describe("safeDeepClone inner-clone WeakSet invariant (Finding 24)", () => {
    test("input array containing reference back to outer object does not infinite-loop", () => {
      // After the path-stack fix in Finding 4 and the clone-once refactor in
      // Finding 15, processNode walks the cloned tree only — the upfront
      // safeDeepClone breaks any cycle in the user input before processNode
      // sees it. This test pins that invariant: an input where an array
      // contains a reference back to the outer object must terminate without
      // stack overflow, and the resulting structure must be JSON-serializable
      // (i.e. acyclic).
      const outer: any = { name: "root" };
      const arr: any[] = [1, outer, 2];
      outer.nested = arr;
      // Also seed pollution so processNode actually records the array into the
      // polluted tree — the path under test is "polluted-tree references into
      // the cloned tree are safe / acyclic".
      const wrapper = { items: arr };

      const start = Date.now();
      const result: any = sanitize(wrapper);
      const duration = Date.now() - start;

      expect(duration).toBeLessThan(1000);
      // Cleaned output is JSON-serializable (no cycles leaked through).
      expect(() => JSON.stringify(result)).not.toThrow();
    });

    test("polluted tree built from cloned input is itself acyclic", () => {
      // A direct test of the detachment invariant: even when the input has a
      // self-cycle that overlaps with a polluted (array) entry, the polluted
      // tree captured by detectAndReduce must be JSON-serializable.
      const outer: any = { x: 1 };
      const polluted: any[] = ["a", "b"];
      outer.dup = polluted;
      // Inject a back-edge: array element references the outer object. The
      // upfront clone breaks this cycle before processNode walks the cloned
      // tree.
      polluted.push(outer);

      const result: any = sanitize({ root: outer });
      // No infinite loop and JSON.stringify succeeds (acyclic) — the polluted
      // tree references only nodes inside the detached cloned tree.
      expect(() => JSON.stringify(result)).not.toThrow();
    });
  });

  describe("pollutedKeys deduplication for nested arrays (Finding 1)", () => {
    test("nested array { a: [[1,2], [3,4]] } records pollution exactly once under keepLast", async () => {
      // Before the fix, processNode recorded one pollutedKeys entry per array
      // level it visited at the same path — producing
      //   pollutedKeys: ["body.a", "body.a", "body.a"]
      // for { a: [[1,2], [3,4]] }. The expected behavior is that only the
      // outermost array site at a given path records pollution, so the user-
      // facing `pollutedKeys` list reports each affected leaf exactly once.
      const calls: { source: string; pollutedKeys: string[] }[] = [];
      const app = express();
      app.use(express.json());
      app.use(
        hppx({
          checkBodyContentType: "any",
          logPollution: false,
          onPollutionDetected: (_req, info) =>
            calls.push({ source: info.source, pollutedKeys: info.pollutedKeys }),
        }),
      );
      app.post("/t", (req: any, res) =>
        res.json({ body: req.body, bodyPolluted: req.bodyPolluted ?? {} }),
      );

      const res = await request(app)
        .post("/t")
        .set("content-type", "application/json")
        .send({
          a: [
            [1, 2],
            [3, 4],
          ],
        });

      expect(res.status).toBe(200);
      // pollutedKeys must contain exactly one entry for "body.a" — no
      // duplicates from inner-array recursion.
      expect(calls).toHaveLength(1);
      expect(calls[0]!.pollutedKeys).toEqual(["body.a"]);
      // The polluted tree shape is unchanged: the outer array (which is the
      // useful capture) is still recorded at body.a.
      expect(res.body.bodyPolluted).toEqual({
        a: [
          [1, 2],
          [3, 4],
        ],
      });
    });

    test("nested array sanitize() also records once under combine strategy", () => {
      // Combine still emits the security signal for arrays (pollution is
      // recorded for ALL strategies). The dedup must apply identically — a
      // nested array site must not produce duplicate pollutedKeys entries.
      const input = {
        a: [
          [1, 2],
          [3, 4],
        ],
      };

      // Direct sanitize() doesn't expose pollutedKeys, so we exercise the
      // middleware path which surfaces them via onPollutionDetected.
      const calls: { source: string; pollutedKeys: string[] }[] = [];
      const middleware = hppx({
        mergeStrategy: "combine",
        logPollution: false,
        onPollutionDetected: (_req, info) =>
          calls.push({ source: info.source, pollutedKeys: info.pollutedKeys }),
      });
      const req: any = { query: input, headers: {} };
      const res: any = {};
      middleware(req, res, () => undefined);

      expect(calls).toHaveLength(1);
      expect(calls[0]!.source).toBe("query");
      expect(calls[0]!.pollutedKeys).toEqual(["query.a"]);
      // Polluted tree captures the outer array.
      expect(req.queryPolluted).toEqual({
        a: [
          [1, 2],
          [3, 4],
        ],
      });
    });

    test("deeply nested arrays-of-arrays still record once at the outermost site", () => {
      // A 3-level deep array nest under a single key must produce exactly
      // one pollutedKeys entry — the inner two levels are skipped due to the
      // inArray flag.
      const calls: { source: string; pollutedKeys: string[] }[] = [];
      const middleware = hppx({
        logPollution: false,
        onPollutionDetected: (_req, info) =>
          calls.push({ source: info.source, pollutedKeys: info.pollutedKeys }),
      });
      const req: any = {
        query: { deep: [[[1, 2]], [[3, 4]]] },
        headers: {},
      };
      const res: any = {};
      middleware(req, res, () => undefined);

      expect(calls).toHaveLength(1);
      expect(calls[0]!.pollutedKeys).toEqual(["query.deep"]);
      expect(req.queryPolluted).toEqual({ deep: [[[1, 2]], [[3, 4]]] });
    });

    test("arrays of objects: pollutedKeys deduped per distinct leaf path", () => {
      // Input has two top-level arrays at distinct paths plus two inner
      // arrays at the SAME path (y.z, one in each object element):
      //   - x: [[1,2], [3,4]]                          → "query.x" once
      //   - y: [{ z: [10, 20] }, { z: [30, 40] }]      → "query.y" once
      //         The two inner z-arrays are at the same path "query.y.z"
      //         (different positions in the array, same dotted path);
      //         pollutedKeys must report each distinct path exactly once.
      const calls: { source: string; pollutedKeys: string[] }[] = [];
      const middleware = hppx({
        logPollution: false,
        onPollutionDetected: (_req, info) =>
          calls.push({ source: info.source, pollutedKeys: info.pollutedKeys }),
      });
      const req: any = {
        query: {
          x: [
            [1, 2],
            [3, 4],
          ],
          y: [{ z: [10, 20] }, { z: [30, 40] }],
        },
        headers: {},
      };
      const res: any = {};
      middleware(req, res, () => undefined);

      expect(calls).toHaveLength(1);
      // Each distinct leaf path appears once in pollutedKeys, even though
      // y.z is an array site visited twice (one per outer-array element).
      expect(calls[0]!.pollutedKeys.sort()).toEqual(["query.x", "query.y", "query.y.z"]);
    });

    test("flat (non-nested) arrays continue to record exactly once per path (regression)", () => {
      // Sanity check: the dedup must NOT suppress legitimate single-array
      // pollution. A flat array at `x` and a flat array at `y` should
      // produce two pollutedKeys entries, one per distinct path.
      const calls: { source: string; pollutedKeys: string[] }[] = [];
      const middleware = hppx({
        logPollution: false,
        onPollutionDetected: (_req, info) =>
          calls.push({ source: info.source, pollutedKeys: info.pollutedKeys }),
      });
      const req: any = {
        query: { x: [1, 2], y: [3, 4] },
        headers: {},
      };
      const res: any = {};
      middleware(req, res, () => undefined);

      expect(calls).toHaveLength(1);
      expect(calls[0]!.pollutedKeys.sort()).toEqual(["query.x", "query.y"]);
    });
  });
});
