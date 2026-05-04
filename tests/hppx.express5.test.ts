/**
 * Express 5 integration tests.
 *
 * Express 5 changed `req.query` to a lazy getter on the prototype chain (no own
 * descriptor). These tests assert that hppx still cleanly replaces it with the
 * sanitized value — i.e. the user observes the reduced value on `req.query`,
 * not just on `req.queryPolluted`.
 */
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
