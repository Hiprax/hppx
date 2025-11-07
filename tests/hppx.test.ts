import express from "express";
import request from "supertest";
import hppx from "../src/index";

function buildApp(opts?: Parameters<typeof hppx>[0]) {
  const app = express();
  if (opts?.checkBodyContentType !== "none") {
    app.use(express.urlencoded({ extended: true }));
    app.use(express.json());
  }
  if (!opts) app.use(hppx());
  else app.use(hppx(opts));

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
  router.use(hppx({ whitelist: "b" }));
  const sub = express.Router();
  sub.use(hppx({ whitelist: ["b", "c"] }));
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
    const res = await request(app).get(
      "/search?firstname=John&firstname=Alice"
    );
    expect(res.body).toEqual({
      query: { firstname: "Alice" },
      queryPolluted: { firstname: ["John", "Alice"] },
      body: {},
      bodyPolluted: {},
    });
  });

  it("mixed parameters", async () => {
    const app = buildApp();
    const res = await request(app).get(
      "/search?title=PhD&firstname=John&firstname=Alice&age=40"
    );
    expect(res.body).toEqual({
      query: { title: "PhD", firstname: "Alice", age: "40" },
      queryPolluted: { firstname: ["John", "Alice"] },
      body: {},
      bodyPolluted: {},
    });
  });

  it("no pollution", async () => {
    const app = buildApp();
    const res = await request(app).get(
      "/search?title=PhD&firstname=Alice&age=40"
    );
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
    const res = await request(app).get(
      "/search?title=PhD&firstname=John&firstname=Alice&age=40"
    );
    expect(res.body).toEqual({
      query: { title: "PhD", firstname: ["John", "Alice"], age: "40" },
      body: {},
    });
  });

  it("whitelist one parameter", async () => {
    const app = buildApp({ whitelist: "firstname" });
    const res = await request(app).get(
      "/search?title=PhD&firstname=John&firstname=Alice&age=40&age=41"
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
    app.use(hppx());
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
      "/search?user.tags=1&user.tags=2&user.name=Ann&user.name=Bob"
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
    expect(res.body).toEqual({
      query: { x: ["1", "2"] },
      queryPolluted: {},
      body: {},
      bodyPolluted: {},
    });
  });
});
