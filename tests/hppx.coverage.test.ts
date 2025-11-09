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
    test("uses default branch when strategy is unrecognized internally", () => {
      // This tests the default case in the switch statement (line 174)
      // We need to pass an invalid strategy to hit the default case
      const input = { x: [1, 2, 3] };

      // Cast to any to bypass TypeScript validation and test internal default
      const result = sanitize(input, { mergeStrategy: "invalid" as any });

      // Should behave like keepLast (default case returns last value)
      expect(result.x).toBe(3);
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
});
