/**
 * Express 5 integration tests.
 *
 * Express 5 changed `req.query` to a lazy getter on the prototype chain (no own
 * descriptor). These tests assert that hppx still cleanly replaces it with the
 * sanitized value — i.e. the user observes the reduced value on `req.query`,
 * not just on `req.queryPolluted`.
 */
import querystring from "node:querystring";
import express from "express";
import request from "supertest";
import hppx from "../src/index";

describe("hppx - Express 5 integration", () => {
  test("sanitizes req.query when Express 5 lazy getter is in play", async () => {
    let observedQueryX: unknown = null;
    let observedPollutedX: unknown = null;

    const app = express();
    app.use(hppx({ logPollution: false }));
    app.get("/test", (req, res) => {
      observedQueryX = (req.query as Record<string, unknown>).x;
      observedPollutedX = ((req as any).queryPolluted as Record<string, unknown> | undefined)?.x;
      res.json({});
    });

    const res = await request(app).get("/test?x=1&x=2");

    expect(res.status).toBe(200);
    // `keepLast` (default) reduces ['1','2'] to '2' — must be observable on req.query,
    // not just req.queryPolluted.
    expect(observedQueryX).toBe("2");
    // Original duplicates must still be captured for downstream inspection.
    expect(observedPollutedX).toEqual(["1", "2"]);
  });

  test("parses the query string exactly once per request (Express 5 req.query getter re-parses on every read)", async () => {
    let parses = 0;
    const parsesSeenByHandler: number[] = [];
    let firstRead: unknown = null;
    let secondRead: unknown = null;
    let pollutedX: unknown = null;

    const app = express();
    app.set("query parser", (str: string) => {
      parses++;
      return querystring.parse(str);
    });
    app.use(hppx({ logPollution: false }));
    app.get("/t", (req, res) => {
      parsesSeenByHandler.push(parses);
      firstRead = req.query;
      secondRead = req.query;
      pollutedX = ((req as any).queryPolluted as Record<string, unknown>).x;
      parsesSeenByHandler.push(parses);
      res.json({});
    });

    const cases = [
      { path: "/t?x=1&x=2", reduced: "2", polluted: ["1", "2"] },
      { path: "/t?x=3&x=4", reduced: "4", polluted: ["3", "4"] },
    ];
    for (const { path, reduced, polluted } of cases) {
      parses = 0;
      parsesSeenByHandler.length = 0;
      const res = await request(app).get(path);
      expect(res.status).toBe(200);
      // hppx read req.query once; the handler's reads hit the sanitized own
      // property and never re-run the parser.
      expect(parses).toBe(1);
      expect(parsesSeenByHandler).toEqual([1, 1]);
      expect(secondRead).toBe(firstRead);
      // Reduced on req.query, duplicates kept on queryPolluted.
      expect((firstRead as Record<string, unknown>).x).toBe(reduced);
      expect(pollutedX).toEqual(polluted);
    }
  });

  test("Express 5 req.query is a writable own property after middleware runs", async () => {
    let descriptor: PropertyDescriptor | undefined;

    const app = express();
    app.use(hppx({ logPollution: false }));
    app.get("/test", (req, res) => {
      // Should now be an own data property (we shadowed the proto getter)
      descriptor = Object.getOwnPropertyDescriptor(req, "query");
      res.json({});
    });

    await request(app).get("/test?x=1&x=2");

    expect(descriptor).toBeDefined();
    expect(descriptor?.writable).toBe(true);
    expect(descriptor?.configurable).toBe(true);
  });

  test("emits a warning (not silent fail) when req.query is non-configurable + non-writable", async () => {
    const warnings: string[] = [];

    const app = express();
    // Pre-freeze req.query so hppx cannot redefine or assign to it.
    app.use((req, _res, next) => {
      Object.defineProperty(req, "query", {
        value: { x: ["1", "2"] },
        writable: false,
        configurable: false,
        enumerable: true,
      });
      next();
    });
    app.use(
      hppx({
        logPollution: false,
        logger: (msg) => {
          if (typeof msg === "string") warnings.push(msg);
        },
      }),
    );
    app.get("/test", (_req, res) => res.json({}));

    const res = await request(app).get("/test?ignored=true");

    expect(res.status).toBe(200);
    // Must surface the failure — not silently fail-open.
    expect(warnings.some((w) => /Could not write sanitized value to req\.query/.test(w))).toBe(
      true,
    );
  });

  test("sanitizes req.body in Express 5 with json content-type", async () => {
    let observedBody: unknown = null;

    const app = express();
    app.use(express.json());
    app.use(hppx({ checkBodyContentType: "any", logPollution: false }));
    app.post("/test", (req, res) => {
      observedBody = req.body;
      res.json({});
    });

    await request(app)
      .post("/test")
      .set("content-type", "application/json")
      .send({ x: ["1", "2"] });

    expect(observedBody).toEqual({ x: "2" });
  });
});
