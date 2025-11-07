import express from "express";
import request from "supertest";
import hppx from "../src/index";

describe("hppx - additional edge cases and branches", () => {
  function appWith(opts?: Parameters<typeof hppx>[0]) {
    const app = express();
    app.use(express.urlencoded({ extended: true }));
    app.use(express.json());
    app.use(hppx(opts || {}));
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
    const { sanitize } = require("../src/index");
    const cleaned = sanitize({ ["a\u0000b"]: 1, ["..."]: "v", normal: "ok" } as any, {
      mergeStrategy: "keepLast",
    });
    // Null-byte key removed, malformed key (...) removed, normal key kept
    expect(cleaned).toEqual({ normal: "ok" });
    expect(cleaned["a\u0000b"]).toBeUndefined();
    expect(cleaned["..."]).toBeUndefined();
  });

  it("sanitize allows single dot as valid key", () => {
    const { sanitize } = require("../src/index");
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
    app.use(hppx({ sources: ["body" as any], checkBodyContentType: "any" }));
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
    const { sanitize } = require("../src/index");
    const cleaned = sanitize({ x: [[1], [2]] } as any, { mergeStrategy: "combine" });
    expect(cleaned).toEqual({ x: [1, 2] });
  });
});
