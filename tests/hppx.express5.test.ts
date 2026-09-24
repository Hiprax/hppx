/**
 * Express 5 integration tests.
 *
 * Express 5 changed `req.query` to a lazy getter on the prototype chain (no own
 * descriptor). These tests assert that hppx still cleanly replaces it with the
 * sanitized value — i.e. the user observes the reduced value on `req.query`,
 * not just on `req.queryPolluted`.
 *
 * Express 5 also delivers wildcard (splat) route params such as `/files/*filepath`
 * as arrays of path segments. The "Express 5 wildcard (splat) params" describe
 * pins how each mounting style interacts with that (README FAQ 8).
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

// Express 5 path-to-regexp v8 wildcards: GET /files/a/b/c.txt on `/files/*filepath`
// yields req.params.filepath === ["a", "b", "c.txt"]. hppx cannot tell a framework
// splat array from an injected duplicate, so the pins below document the limitation,
// the workaround, and why app-level mounting never sees route params.
describe("hppx - Express 5 wildcard (splat) params", () => {
  const SPLAT_ROUTE = "/files/*filepath";

  interface Observed {
    params: Record<string, unknown>;
    hasParamsPolluted: boolean;
    paramsPolluted: unknown;
    query: Record<string, unknown>;
    queryPolluted: unknown;
  }

  const observe = (req: express.Request, res: express.Response) => {
    const observed: Observed = {
      params: req.params,
      hasParamsPolluted: Object.prototype.hasOwnProperty.call(req, "paramsPolluted"),
      paramsPolluted: req.paramsPolluted ?? null,
      query: req.query as Record<string, unknown>,
      queryPolluted: req.queryPolluted ?? null,
    };
    res.json(observed);
  };

  test("documented limitation: route-level hppx() with default sources reduces a multi-segment splat array to its last segment and flags it", async () => {
    const events: { source: string; pollutedKeys: string[] }[] = [];
    const logs: unknown[] = [];
    const app = express();
    app.get(
      SPLAT_ROUTE,
      hppx({
        // The pollution log line is under test here, so logging stays on.
        logger: (entry) => {
          logs.push(entry);
        },
        onPollutionDetected: (_req, info) => {
          events.push({ source: info.source, pollutedKeys: info.pollutedKeys });
        },
      }),
      observe,
    );

    const res = await request(app).get("/files/a/b/c.txt");

    expect(res.status).toBe(200);
    const body = res.body as Observed;
    // keepLast (default) keeps only the final segment; the full path survives
    // only on the side channel.
    expect(body.params).toEqual({ filepath: "c.txt" });
    expect(body.hasParamsPolluted).toBe(true);
    expect(body.paramsPolluted).toEqual({ filepath: ["a", "b", "c.txt"] });
    expect(events).toEqual([{ source: "params", pollutedKeys: ["params.filepath"] }]);
    expect(logs).toEqual([
      "[hppx] HTTP Parameter Pollution detected - 1 parameter(s) affected: params.filepath",
    ]);
    // Negative: no query pollution is invented for a request without a query string.
    expect(body.query).toEqual({});
    expect(body.queryPolluted).toEqual({});
  });

  test("documented limitation: a single-segment splat is still an array, so it is flagged as pollution too", async () => {
    const app = express();
    app.get(SPLAT_ROUTE, hppx({ logPollution: false }), observe);

    const res = await request(app).get("/files/c.txt");

    expect(res.status).toBe(200);
    const body = res.body as Observed;
    // The reduced value happens to equal the only segment, but the request is
    // still reported: a required `*name` wildcard always yields an array, even
    // for one segment.
    expect(body.params).toEqual({ filepath: "c.txt" });
    expect(body.hasParamsPolluted).toBe(true);
    expect(body.paramsPolluted).toEqual({ filepath: ["c.txt"] });
    // Negative: no query pollution is invented for a request without a query string.
    expect(body.query).toEqual({});
    expect(body.queryPolluted).toEqual({});
  });

  test("documented limitation: route-level strict mode rejects every request on a required wildcard route with 400 before the handler runs", async () => {
    let handlerCalls = 0;
    const app = express();
    app.get(SPLAT_ROUTE, hppx({ strict: true, logPollution: false }), (_req, res) => {
      handlerCalls++;
      res.json({ ok: true });
    });

    for (const path of ["/files/a/b/c.txt", "/files/c.txt"]) {
      const res = await request(app).get(path);
      expect(res.status).toBe(400);
      expect(res.body).toEqual({
        error: "Bad Request",
        message: "HTTP Parameter Pollution detected",
        pollutedParameters: ["params.filepath"],
        code: "HPP_DETECTED",
      });
    }
    // Negative: strict mode short-circuits, the route handler never runs.
    expect(handlerCalls).toBe(0);
  });

  test('documented workaround: sources ["query", "body"] on a wildcard route leaves the splat array intact', async () => {
    const app = express();
    app.get(SPLAT_ROUTE, hppx({ sources: ["query", "body"], logPollution: false }), observe);

    const res = await request(app).get("/files/a/b/c.txt");

    expect(res.status).toBe(200);
    const body = res.body as Observed;
    expect(body.params).toEqual({ filepath: ["a", "b", "c.txt"] });
    // Negative: params is not a processed source, so no side channel is attached.
    expect(body.hasParamsPolluted).toBe(false);
    expect(body.paramsPolluted).toBeNull();
  });

  test('documented workaround: sources ["query", "body"] still reduces duplicate query parameters on the wildcard route', async () => {
    const app = express();
    app.get(SPLAT_ROUTE, hppx({ sources: ["query", "body"], logPollution: false }), observe);

    const res = await request(app).get("/files/a/b?x=1&x=2");

    expect(res.status).toBe(200);
    const body = res.body as Observed;
    expect(body.query).toEqual({ x: "2" });
    expect(body.queryPolluted).toEqual({ x: ["1", "2"] });
    // Negative: query protection does not touch the splat array.
    expect(body.params).toEqual({ filepath: ["a", "b"] });
    expect(body.hasParamsPolluted).toBe(false);
  });

  test('documented workaround: strict mode with sources ["query", "body"] accepts the splat but still rejects duplicate query parameters', async () => {
    let handlerCalls = 0;
    const app = express();
    app.get(
      SPLAT_ROUTE,
      hppx({ sources: ["query", "body"], strict: true, logPollution: false }),
      (req, res) => {
        handlerCalls++;
        res.json({ params: req.params });
      },
    );

    const accepted = await request(app).get("/files/a/b/c.txt");
    expect(accepted.status).toBe(200);
    expect(accepted.body).toEqual({ params: { filepath: ["a", "b", "c.txt"] } });

    const rejected = await request(app).get("/files/a/b?x=1&x=2");
    expect(rejected.status).toBe(400);
    expect(rejected.body).toEqual({
      error: "Bad Request",
      message: "HTTP Parameter Pollution detected",
      pollutedParameters: ["query.x"],
      code: "HPP_DETECTED",
    });
    // Negative: only the accepted request reached the handler.
    expect(handlerCalls).toBe(1);
  });

  test("global app.use(hppx()) runs before routing, sees an empty params object, and leaves the splat array untouched", async () => {
    for (const options of [{}, { strict: true }]) {
      const events: string[] = [];
      let appLevelParamKeys: string[] | null = null;
      const app = express();
      // Records what the app-level layer (and so the global hppx) sees in req.params.
      app.use((req, _res, next) => {
        appLevelParamKeys = Object.keys(req.params);
        next();
      });
      app.use(
        hppx({
          ...options,
          logPollution: false,
          onPollutionDetected: (_req, info) => {
            events.push(info.source);
          },
        }),
      );
      app.get(SPLAT_ROUTE, observe);

      const res = await request(app).get("/files/a/b/c.txt");

      expect(appLevelParamKeys).toEqual([]);
      // Negative: even strict mode does not reject, because the route params
      // did not exist yet when the app-level instance ran.
      expect(res.status).toBe(200);
      const body = res.body as Observed;
      expect(body.params).toEqual({ filepath: ["a", "b", "c.txt"] });
      // params was processed while still empty, so its side channel is empty.
      expect(body.paramsPolluted).toEqual({});
      expect(events).toEqual([]);
    }
  });

  test("global plus route-level hppx() on the same request: the global instance marks params processed while empty, so the route-level instance leaves the splat array untouched", async () => {
    for (const routeOptions of [{}, { strict: true }]) {
      const events: string[] = [];
      const app = express();
      app.use(hppx({ logPollution: false }));
      app.get(
        SPLAT_ROUTE,
        hppx({
          ...routeOptions,
          logPollution: false,
          onPollutionDetected: (_req, info) => {
            events.push(info.source);
          },
        }),
        observe,
      );

      const res = await request(app).get("/files/a/b/c.txt");

      // Negative: the route-level instance neither reduces the splat nor rejects
      // the request in strict mode; it only restores whitelisted entries.
      expect(res.status).toBe(200);
      const body = res.body as Observed;
      expect(body.params).toEqual({ filepath: ["a", "b", "c.txt"] });
      expect(body.paramsPolluted).toEqual({});
      expect(events).toEqual([]);
    }
  });
});
