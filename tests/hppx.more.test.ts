import express from "express";
import request from "supertest";
import hppx, { sanitize } from "../src/index";

describe("hppx - additional edge cases and branches", () => {
  function appWith(opts?: Parameters<typeof hppx>[0]) {
    const app = express();
    app.use(express.urlencoded({ extended: true }));
    app.use(express.json());
    // Disable logging by default in tests
    const testOpts = { logPollution: false, ...(opts || {}) };
    app.use(hppx(testOpts));
    app.get("/t", (req, res) =>
      res.json({
        query: req.query || {},
        queryPolluted: (req as any).queryPolluted || {},
        body: req.body || {},
        bodyPolluted: (req as any).bodyPolluted || {},
      }),
    );
    return app;
  }

  it("mergeStrategy validation rejects invalid values", () => {
    // Options validation now throws on invalid merge strategy
    expect(() => {
      appWith({ mergeStrategy: "weird" as any });
    }).toThrow(TypeError);
    expect(() => {
      appWith({ mergeStrategy: "weird" as any });
    }).toThrow("mergeStrategy must be");
  });

  it("excludePaths with non-matching pattern does not exclude", async () => {
    const app = appWith({ excludePaths: ["/nope", "/admin*"] });
    const res = await request(app).get("/t?a=1&a=2");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      query: { a: "2" },
      queryPolluted: { a: ["1", "2"] },
      body: {},
      bodyPolluted: {},
    });
  });

  it("prunes empty objects from queryPolluted after whitelisted restore", async () => {
    const app = appWith({ whitelist: ["user.tags"] });
    const res = await request(app).get("/t?user.tags=1&user.tags=2");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      query: { user: { tags: ["1", "2"] } },
      queryPolluted: {},
      body: {},
      bodyPolluted: {},
    });
  });

  it("expands bracket notation into nested objects", async () => {
    const app = appWith({ whitelist: ["a.b.c"] });
    // a[b][c]=1&a[b][c]=2
    const res = await request(app).get("/t?a[b][c]=1&a[b][c]=2");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      query: { a: { b: { c: ["1", "2"] } } },
      queryPolluted: {},
      body: {},
      bodyPolluted: {},
    });
  });

  it("does not process body when checkBodyContentType is 'none'", async () => {
    const app = express();
    app.use(express.urlencoded({ extended: true }));
    app.use(
      hppx({
        checkBodyContentType: "none",
      }),
    );
    app.post("/t", (req, res) =>
      res.json({
        body: req.body || {},
        bodyPolluted: (req as any).bodyPolluted || {},
      }),
    );
    const res = await request(app)
      .post("/t")
      .set("content-type", "application/x-www-form-urlencoded")
      .send("x=1&x=2");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      body: { x: ["1", "2"] },
      bodyPolluted: {},
    });
  });

  it("trims string values when trimValues is true", async () => {
    const app = appWith({ trimValues: true });
    const res = await request(app).get("/t?name=%20john%20&name=%20doe%20");
    // keepLast with trimming applied
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      query: { name: "doe" },
      queryPolluted: { name: [" john ", " doe "] },
      body: {},
      bodyPolluted: {},
    });
  });

  it("sanitize removes null-char keys and malformed keys", () => {
    const cleaned = sanitize({ ["a\u0000b"]: 1, ["..."]: "v", normal: "ok" } as any, {
      mergeStrategy: "keepLast",
    });
    // Null-byte key removed, malformed key (...) removed, normal key kept
    expect(cleaned).toEqual({ normal: "ok" });
    expect(cleaned["a\u0000b"]).toBeUndefined();
    expect(cleaned["..."]).toBeUndefined();
  });

  it("sanitize allows single dot as valid key", () => {
    const cleaned = sanitize({ ["."]: "v", normal: "ok" } as any, { mergeStrategy: "keepLast" });
    // Single dot is valid and should be kept
    expect(cleaned["."]).toBe("v");
    expect(cleaned.normal).toBe("ok");
  });

  it("whitelist prefix applies to entire subtree", async () => {
    const app = appWith({ whitelist: ["user"] });
    const res = await request(app).get(
      "/t?user.tags=1&user.tags=2&user.name=Ann&user.name=Bob&other=1&other=2",
    );
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      query: { user: { tags: ["1", "2"], name: ["Ann", "Bob"] }, other: "2" },
      queryPolluted: { other: ["1", "2"] },
      body: {},
      bodyPolluted: {},
    });
  });

  it("skips non-plain-object request parts gracefully", async () => {
    const app = express();
    // Set non-plain body before middleware
    app.use((req, _res, next) => {
      (req as any).body = "literal";
      next();
    });
    app.use(hppx({ sources: ["body" as any], checkBodyContentType: "any", logPollution: false }));
    app.post("/t", (req, res) =>
      res.json({
        body: (req as any).body,
        bodyPolluted: (req as any).bodyPolluted || {},
      }),
    );
    const res = await request(app).post("/t");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ body: "literal", bodyPolluted: {} });
  });

  it("combine strategy flattens arrays-of-arrays", () => {
    const cleaned = sanitize({ x: [[1], [2]] } as any, { mergeStrategy: "combine" });
    expect(cleaned).toEqual({ x: [1, 2] });
  });

  describe("Multi-middleware option precedence (documented behavior)", () => {
    // The README "Multi-Middleware Stacking" section documents that when a
    // subsequent hppx() runs on a source that has already been processed by an
    // earlier instance, only the second middleware's `whitelist` is honored.
    // All other options — including `strict` — are silently ignored. These
    // tests pin that contract so it cannot regress unnoticed.

    it("ignores strict:true on the second middleware after the first cleaned the source", async () => {
      const app = express();
      app.use(express.urlencoded({ extended: true }));
      app.use(express.json());
      // First middleware: default keepLast, NOT strict — cleans the source.
      app.use(hppx({ logPollution: false }));
      // Second middleware: strict:true. Per the documented contract this MUST
      // be silently ignored because the source has already been processed; the
      // request must NOT receive a 400 response.
      app.use(hppx({ strict: true, logPollution: false }));
      app.get("/multi", (req, res) =>
        res.json({
          query: req.query,
          queryPolluted: (req as any).queryPolluted || {},
        }),
      );

      const res = await request(app).get("/multi?x=1&x=2");
      // The second middleware's strict:true was a no-op; the response is the
      // route handler's 200 with the cleaned query.
      expect(res.status).toBe(200);
      expect(res.body.query).toEqual({ x: "2" });
      expect(res.body.queryPolluted).toEqual({ x: ["1", "2"] });
    });

    it("ignores onPollutionDetected on the second middleware after the first cleaned the source", async () => {
      const firstCalls: { source: string; pollutedKeys: string[] }[] = [];
      const secondCalls: { source: string; pollutedKeys: string[] }[] = [];
      const app = express();
      app.use(express.urlencoded({ extended: true }));
      app.use(express.json());
      app.use(
        hppx({
          logPollution: false,
          onPollutionDetected: (_req, info) => firstCalls.push(info),
        }),
      );
      app.use(
        hppx({
          logPollution: false,
          // This callback MUST NOT fire for the already-processed source.
          onPollutionDetected: (_req, info) => secondCalls.push(info),
        }),
      );
      app.get("/multi", (_req, res) => res.json({}));

      await request(app).get("/multi?a=1&a=2");

      expect(firstCalls.length).toBe(1);
      expect(firstCalls[0]?.source).toBe("query");
      // Second middleware's callback was silently dropped.
      expect(secondCalls.length).toBe(0);
    });

    it("a subsequent middleware with a wider whitelist restores additional fields", async () => {
      // The whitelist on the second middleware IS honored — that is the
      // documented purpose of multi-middleware stacking. Confirm that part of
      // the contract too, so a future change cannot accidentally drop it.
      const app = express();
      app.use(express.urlencoded({ extended: true }));
      app.use(hppx({ whitelist: ["a"], logPollution: false }));
      app.use(hppx({ whitelist: ["b"], logPollution: false }));
      app.get("/multi", (req, res) =>
        res.json({
          query: req.query,
          queryPolluted: (req as any).queryPolluted || {},
        }),
      );

      const res = await request(app).get("/multi?a=1&a=2&b=3&b=4&c=5&c=6");
      expect(res.status).toBe(200);
      // Both whitelisted parameters preserved as arrays; non-whitelisted is reduced.
      expect(res.body.query).toEqual({ a: ["1", "2"], b: ["3", "4"], c: "6" });
      // Only c remains in queryPolluted.
      expect(res.body.queryPolluted).toEqual({ c: ["5", "6"] });
    });
  });
});
