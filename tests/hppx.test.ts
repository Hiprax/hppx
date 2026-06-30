import express from "express";
import request from "supertest";
import hppx from "../src/index";

function buildApp(opts?: Parameters<typeof hppx>[0]) {
  const app = express();
  if (opts?.checkBodyContentType !== "none") {
    app.use(express.urlencoded({ extended: true }));
    app.use(express.json());
  }
  // Disable logging in tests by default to keep output clean
  const testOpts = opts ? { logPollution: false, ...opts } : { logPollution: false };
  if (!opts) app.use(hppx(testOpts));
  else app.use(hppx(testOpts));

  const includeQuery = opts?.sources ? opts.sources.includes("query" as any) : true;
  const includeBody = opts?.sources ? opts.sources.includes("body" as any) : true;
  const includeBodyPolluted = includeBody && opts?.sources === undefined;

  const handler = (req: any, res: any) => {
    const base: any = {
      query: req.query || {},
      body: req.body || {},
    };
    if (includeQuery) base.queryPolluted = req.queryPolluted || {};
    if (includeBodyPolluted) base.bodyPolluted = req.bodyPolluted || {};
    res.json(base);
  };

  app.get("/search", handler);
  app.post("/search", handler);

  // route tree for multi-middleware tests
  const router = express.Router();
  router.use(hppx({ whitelist: "b", logPollution: false }));
  const sub = express.Router();
  sub.use(hppx({ whitelist: ["b", "c"], logPollution: false }));
  sub.get("/", handler);
  app.use("/x", router);
  router.use("/y", sub);

  return app;
}

describe("hppx - query handling", () => {
  it("handles identical parameters (keep last)", async () => {
    const app = buildApp();
    const res = await request(app).get("/search?firstname=John&firstname=John");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      query: { firstname: "John" },
      queryPolluted: { firstname: ["John", "John"] },
      body: {},
      bodyPolluted: {},
    });
  });

  it("handles two same parameters with different values (keep last)", async () => {
    const app = buildApp();
    const res = await request(app).get("/search?firstname=John&firstname=Alice");
    expect(res.body).toEqual({
      query: { firstname: "Alice" },
      queryPolluted: { firstname: ["John", "Alice"] },
      body: {},
      bodyPolluted: {},
    });
  });

  it("mixed parameters", async () => {
    const app = buildApp();
    const res = await request(app).get("/search?title=PhD&firstname=John&firstname=Alice&age=40");
    expect(res.body).toEqual({
      query: { title: "PhD", firstname: "Alice", age: "40" },
      queryPolluted: { firstname: ["John", "Alice"] },
      body: {},
      bodyPolluted: {},
    });
  });

  it("no pollution", async () => {
    const app = buildApp();
    const res = await request(app).get("/search?title=PhD&firstname=Alice&age=40");
    expect(res.body).toEqual({
      query: { title: "PhD", firstname: "Alice", age: "40" },
      queryPolluted: {},
      body: {},
      bodyPolluted: {},
    });
  });

  it("no query", async () => {
    const app = buildApp();
    const res = await request(app).get("/search");
    expect(res.body).toEqual({
      query: {},
      queryPolluted: {},
      body: {},
      bodyPolluted: {},
    });
  });

  it("checkQuery=false leaves arrays", async () => {
    const app = buildApp({ sources: ["body", "params" as any] });
    const res = await request(app).get("/search?title=PhD&firstname=John&firstname=Alice&age=40");
    expect(res.body).toEqual({
      query: { title: "PhD", firstname: ["John", "Alice"], age: "40" },
      body: {},
    });
  });

  it("whitelist one parameter", async () => {
    const app = buildApp({ whitelist: "firstname" });
    const res = await request(app).get(
      "/search?title=PhD&firstname=John&firstname=Alice&age=40&age=41",
    );
    expect(res.body).toEqual({
      query: { title: "PhD", firstname: ["John", "Alice"], age: "41" },
      queryPolluted: { age: ["40", "41"] },
      body: {},
      bodyPolluted: {},
    });
  });

  it("multiple middlewares and whitelists", async () => {
    const app = buildApp({ whitelist: "a" });
    const res = await request(app).get("/x/y?a=1&a=2&b=3&b=4&c=5&c=6&d=7&d=8");
    expect(res.body).toEqual({
      query: { a: ["1", "2"], b: ["3", "4"], c: ["5", "6"], d: "8" },
      queryPolluted: { d: ["7", "8"] },
      body: {},
      bodyPolluted: {},
    });
  });
});

describe("hppx - body handling", () => {
  it("urlencoded body, duplicates", async () => {
    const app = buildApp();
    const res = await request(app)
      .post("/search")
      .set("content-type", "application/x-www-form-urlencoded")
      .send("firstname=John&firstname=John");
    expect(res.body).toEqual({
      query: {},
      queryPolluted: {},
      body: { firstname: "John" },
      bodyPolluted: { firstname: ["John", "John"] },
    });
  });

  it("urlencoded mixed", async () => {
    const app = buildApp();
    const res = await request(app)
      .post("/search")
      .set("content-type", "application/x-www-form-urlencoded")
      .send("title=PhD&firstname=John&firstname=Alice&age=40");
    expect(res.body).toEqual({
      query: {},
      queryPolluted: {},
      body: { title: "PhD", firstname: "Alice", age: "40" },
      bodyPolluted: { firstname: ["John", "Alice"] },
    });
  });

  it("no body parser", async () => {
    const app = express();
    app.use(hppx({ logPollution: false }));
    app.post("/search", (req, res) => {
      res.json({
        query: req.query || {},
        queryPolluted: req.queryPolluted || {},
      });
    });
    const res = await request(app)
      .post("/search")
      .set("content-type", "application/x-www-form-urlencoded")
      .send("title=PhD&firstname=John&firstname=Alice&age=40");
    expect(res.body).toEqual({ query: {}, queryPolluted: {} });
  });

  it("json body should not be processed by default", async () => {
    const app = buildApp();
    const res = await request(app)
      .post("/search")
      .set("content-type", "application/json")
      .send({ title: "PhD", firstname: ["John", "Alice"], age: 40 });
    expect(res.body).toEqual({
      query: {},
      queryPolluted: {},
      body: { title: "PhD", firstname: ["John", "Alice"], age: 40 },
      bodyPolluted: {},
    });
  });
});

describe("hppx - nested and strategies", () => {
  it("nested whitelist by dot path", async () => {
    const app = buildApp({ whitelist: ["user.tags"] });
    const res = await request(app).get(
      "/search?user.tags=1&user.tags=2&user.name=Ann&user.name=Bob",
    );
    expect(res.body).toEqual({
      query: { user: { tags: ["1", "2"], name: "Bob" } },
      queryPolluted: { user: { name: ["Ann", "Bob"] } },
      body: {},
      bodyPolluted: {},
    });
  });

  it("keepFirst strategy", async () => {
    const app = buildApp({ mergeStrategy: "keepFirst" });
    const res = await request(app).get("/search?x=1&x=2");
    expect(res.body).toEqual({
      query: { x: "1" },
      queryPolluted: { x: ["1", "2"] },
      body: {},
      bodyPolluted: {},
    });
  });

  it("combine strategy", async () => {
    const app = buildApp({ mergeStrategy: "combine" });
    const res = await request(app).get("/search?x=1&x=2");
    // combine still emits the security signal: req.queryPolluted and the
    // pollutedKeys list reflect the duplicated parameter even though the
    // cleaned data preserves the combined array.
    expect(res.body).toEqual({
      query: { x: ["1", "2"] },
      queryPolluted: { x: ["1", "2"] },
      body: {},
      bodyPolluted: {},
    });
  });

  it("combine strategy fires onPollutionDetected and exposes queryPolluted", async () => {
    const app = express();
    app.use(express.urlencoded({ extended: true }));
    app.use(express.json());
    const events: { source: string; pollutedKeys: string[] }[] = [];
    app.use(
      hppx({
        mergeStrategy: "combine",
        logPollution: false,
        onPollutionDetected: (_req, info) => {
          events.push({ source: info.source, pollutedKeys: info.pollutedKeys });
        },
      }),
    );
    app.get("/c", (req, res) =>
      res.json({
        query: req.query || {},
        queryPolluted: (req as any).queryPolluted || {},
      }),
    );
    const res = await request(app).get("/c?x=1&x=2");
    expect(res.status).toBe(200);
    // Cleaned data: combined array preserved.
    expect(res.body.query).toEqual({ x: ["1", "2"] });
    // Side-channel signal: pollution detected and reported.
    expect(res.body.queryPolluted).toEqual({ x: ["1", "2"] });
    expect(events).toEqual([{ source: "query", pollutedKeys: ["query.x"] }]);
  });
});

// ─── Phase 2 / C1: req.params end-to-end coverage ───────────────────────────
// Express never produces duplicate route params naturally (each :param captures
// exactly one segment). Tests inject them via a route-level pre-middleware that
// sets req.params before hppx runs, exercising the shared detection loop at
// src/index.ts:846-931 for the "params" source.
describe("hppx - req.params end-to-end (C1)", () => {
  // T2.1 — pins current intended behavior: params source reduces duplicate
  // array values and exposes req.paramsPolluted.
  it("T2.1: reduces polluted req.params to keepLast and populates req.paramsPolluted", async () => {
    const app = express();
    app.get(
      "/item",
      (req: any, _res: any, next: any) => {
        // Inject duplicate params — Express would never produce these naturally
        req.params = { id: ["1", "2"], name: "ok" };
        next();
      },
      hppx({ sources: ["params"], logPollution: false }),
      (req: any, res: any) => {
        res.json({ params: req.params, paramsPolluted: req.paramsPolluted });
      },
    );
    const res = await request(app).get("/item");
    expect(res.status).toBe(200);
    // keepLast (default): last element "2" wins; non-duplicate key passes through
    expect(res.body.params).toEqual({ id: "2", name: "ok" });
    // polluted tree retains the full original array for sidechannel auditing
    expect(res.body.paramsPolluted).toEqual({ id: ["1", "2"] });
  });

  // T2.2 — pins current intended behavior: the params source drives
  // onPollutionDetected and strict mode identically to query/body.
  it('T2.2a: params source fires onPollutionDetected with source:"params" and fully-qualified key', async () => {
    const events: { source: string; pollutedKeys: string[] }[] = [];
    const app = express();
    app.get(
      "/item",
      (req: any, _res: any, next: any) => {
        req.params = { id: ["1", "2"], name: "ok" };
        next();
      },
      hppx({
        sources: ["params"],
        logPollution: false,
        onPollutionDetected: (_req, info) => {
          events.push({ source: info.source, pollutedKeys: info.pollutedKeys });
        },
      }),
      (_req: any, res: any) => res.json({}),
    );
    await request(app).get("/item");
    // src/index.ts:957-963: callback fires once per polluted source; the
    // fully-qualified key is "<source>.<key>", so "params.id" here
    expect(events).toEqual([{ source: "params", pollutedKeys: ["params.id"] }]);
  });

  it('T2.2b: params source triggers strict-mode 400 with pollutedParameters including "params.id"', async () => {
    const app = express();
    app.get(
      "/item",
      (req: any, _res: any, next: any) => {
        req.params = { id: ["1", "2"], name: "ok" };
        next();
      },
      hppx({ sources: ["params"], strict: true, logPollution: false }),
      (_req: any, res: any) => res.json({ ok: true }),
    );
    const res = await request(app).get("/item");
    // src/index.ts:971-978: strict mode short-circuits with 400 before next()
    expect(res.status).toBe(400);
    expect(res.body.code).toBe("HPP_DETECTED");
    expect(res.body.pollutedParameters).toEqual(["params.id"]);
  });
});
