import express from "express";
import request from "supertest";
import hppx, { sanitize } from "../src/index";

describe("hppx - strict, excludePaths, callbacks", () => {
  test("strict mode returns 400 with polluted keys", async () => {
    const app = express();
    app.use(hppx({ strict: true, logPollution: false }));
    app.get("/a", (req, res) => res.json({ ok: true }));
    const res = await request(app).get("/a?x=1&x=2&y=3");
    expect(res.status).toBe(400);
    expect(res.body.code).toBe("HPP_DETECTED");
    expect(Array.isArray(res.body.pollutedParameters)).toBe(true);
  });

  test("excludePaths exact and wildcard", async () => {
    const app = express();
    app.use(hppx({ excludePaths: ["/public", "/assets*"], logPollution: false }));
    app.get("/public", (req, res) => res.json({ query: req.query }));
    app.get("/assets/img", (req, res) => res.json({ query: req.query }));
    const r1 = await request(app).get("/public?x=1&x=2");
    const r2 = await request(app).get("/assets/img?x=1&x=2");
    expect(r1.body).toEqual({ query: { x: ["1", "2"] } });
    expect(r2.body).toEqual({ query: { x: ["1", "2"] } });
  });

  test("onPollutionDetected & logger are called", async () => {
    const calls: any[] = [];
    const app = express();
    app.use(
      hppx({
        onPollutionDetected: (_req, info) => calls.push({ type: "cb", info }),
        logger: (err) => calls.push({ type: "log", err: String(err) }),
        logPollution: false,
      }),
    );
    app.get("/b", (req, res) => res.json({}));
    await request(app).get("/b?a=1&a=2");
    expect(calls.some((c) => c.type === "cb")).toBe(true);
  });
});

describe("hppx - content type handling", () => {
  test("body processed when checkBodyContentType=any", async () => {
    const app = express();
    app.use(express.json());
    app.use(hppx({ checkBodyContentType: "any", logPollution: false }));
    app.post("/json", (req, res) =>
      res.json({ body: req.body, bodyPolluted: req.bodyPolluted || {} }),
    );
    const res = await request(app)
      .post("/json")
      .set("content-type", "application/json")
      .send({ x: [1, 2], y: "z" });
    expect(res.body).toEqual({ body: { x: 2, y: "z" }, bodyPolluted: { x: [1, 2] } });
  });
});

describe("hppx - limits and safety", () => {
  test("maxDepth throws and passes error to next", async () => {
    const app = express();
    app.use(
      hppx({
        maxDepth: 2,
        logger: () => {},
        logPollution: false,
      }),
    );
    app.get("/d", (req, res) => res.json({ ok: true }));
    const deep = "a.b.c.d".split(".").reduce((acc: any, k) => ({ [k]: acc }), "v");
    const res = await request(app).get("/d").query(deep);
    // The error should bubble to default handler -> 500
    expect(res.status).toBeGreaterThanOrEqual(500);
  });

  test("maxKeys throws on huge input", async () => {
    const app = express();
    app.use(hppx({ maxKeys: 5, logPollution: false }));
    app.get("/e", (req, res) => res.json({ ok: true }));
    const q: Record<string, string> = {};
    for (let i = 0; i < 10; i++) q["k" + i] = String(i);
    const res = await request(app).get("/e").query(q);
    expect(res.status).toBeGreaterThanOrEqual(500);
  });

  test("dangerous keys are stripped", async () => {
    const app = express();
    app.use(hppx({ logPollution: false }));
    app.get("/f", (req, res) => res.json({ query: req.query }));
    const res = await request(app).get("/f?__proto__=x&constructor=1&safe=ok");
    expect(res.body).toEqual({ query: { safe: "ok" } });
  });
});

describe("sanitize helper", () => {
  test("sanitize respects whitelist and strategies", () => {
    const input = { a: [1, 2], b: [3, 4], user: { tags: ["x", "y"], name: ["A", "B"] } } as any;
    const out = sanitize(input, { whitelist: ["a", "user.tags"], mergeStrategy: "keepFirst" });
    expect(out).toEqual({ a: [1, 2], b: 3, user: { tags: ["x", "y"], name: "A" } });
  });

  test("trimValues and preserveNull behavior", () => {
    const out = sanitize({ a: ["  x  ", null as any], b: "  y  " } as any, {
      mergeStrategy: "keepLast",
      trimValues: true,
      preserveNull: true,
    });
    expect(out).toEqual({ a: null, b: "y" });
  });
});
