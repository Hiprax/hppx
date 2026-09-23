/**
 * Same-leaf key collisions: alternate spellings of one parameter are duplicates.
 *
 * `expandObjectPaths` normalizes dotted and bracketed keys into nested paths, so
 * `a`, `a.`, `a[]` and `[a]` all name the leaf `a`, and `user.role` / `user[role]`
 * both name `user.role`. When two spellings of the same leaf arrive in one
 * request, the wire carried the parameter twice. These tests pin that such
 * duplicates are combined (and therefore detected as pollution) instead of the
 * later spelling silently overwriting the earlier one, which used to bypass
 * `strict` mode, the merge strategies and every pollution signal.
 *
 * Combined values keep the order in which the parser presents keys
 * (`Object.keys` order: integer-like keys first, then insertion order). Structural conflicts, where exactly one side
 * is a plain object, keep last-processed-wins semantics (see the C3 tests in
 * `tests/hppx.edgecases.test.ts`).
 */
import express from "express";
import request from "supertest";
import hppx, { sanitize } from "../src/index";
import type { HppxOptions, MergeStrategy } from "../src/index";

type QueryParser = "simple" | "extended";

function appWith(opts: HppxOptions, parser: QueryParser) {
  const app = express();
  app.set("query parser", parser);
  const handler = jest.fn((req: express.Request, res: express.Response) => {
    res.json({ query: req.query, queryPolluted: req.queryPolluted ?? null });
  });
  app.use(hppx({ logPollution: false, ...opts }));
  app.get("/t", handler);
  return { app, handler };
}

// ---------------------------------------------------------------------------
// Unit tier: sanitize()
// ---------------------------------------------------------------------------

describe("keys that normalize to the same leaf path are duplicates (sanitize)", () => {
  const leafCases: {
    name: string;
    input: Record<string, unknown>;
    first: string;
    last: string;
  }[] = [
    { name: "a then a.", input: { a: "1", "a.": "2" }, first: "1", last: "2" },
    { name: "a then a[]", input: { a: "1", "a[]": "2" }, first: "1", last: "2" },
    { name: "[a] then a", input: { "[a]": "2", a: "1" }, first: "2", last: "1" },
  ];

  it.each(leafCases)(
    "$name: keepLast keeps the last value in key order and leaves no spelling behind",
    ({ input, last }) => {
      const out = sanitize(input, { mergeStrategy: "keepLast" });
      expect(out).toEqual({ a: last });
      expect(Object.keys(out)).toEqual(["a"]);
    },
  );

  it.each(leafCases)("$name: keepFirst keeps the first value in key order", ({ input, first }) => {
    const out = sanitize(input, { mergeStrategy: "keepFirst" });
    expect(out).toEqual({ a: first });
    expect(Object.keys(out)).toEqual(["a"]);
  });

  it.each(leafCases)("$name: combine keeps both values in key order", ({ input, first, last }) => {
    const out = sanitize(input, { mergeStrategy: "combine" });
    expect(out).toEqual({ a: [first, last] });
    expect(Object.keys(out)).toEqual(["a"]);
  });

  it.each<[MergeStrategy, unknown]>([
    ["keepFirst", "user"],
    ["keepLast", "admin"],
    ["combine", ["user", "admin"]],
  ])(
    "nested dotted vs bracketed spellings of user.role are one duplicated leaf (%s)",
    (mergeStrategy, expected) => {
      const out = sanitize<Record<string, unknown>>(
        { "user.role": "user", "user[role]": "admin" },
        { mergeStrategy },
      );
      expect(out).toEqual({ user: { role: expected } });
      expect(Object.keys(out.user as object)).toEqual(["role"]);
    },
  );

  it("a nested object followed by a dotted spelling of its leaf is a duplicate, first in key order wins under keepFirst", () => {
    const input = { user: { role: "user" }, "user.role": "admin" };
    expect(sanitize(input, { mergeStrategy: "keepFirst" })).toEqual({ user: { role: "user" } });
    expect(sanitize(input, { mergeStrategy: "combine" })).toEqual({
      user: { role: ["user", "admin"] },
    });
  });

  it("a dotted spelling followed by the nested object is a duplicate, first in key order wins under keepFirst", () => {
    const input = { "user.role": "admin", user: { role: "user" } };
    expect(sanitize(input, { mergeStrategy: "keepFirst" })).toEqual({ user: { role: "admin" } });
    expect(sanitize(input, { mergeStrategy: "combine" })).toEqual({
      user: { role: ["admin", "user"] },
    });
  });

  it.each<MergeStrategy>(["keepFirst", "keepLast", "combine"])(
    "negative control: distinct keys produce no array and stay unchanged (%s)",
    (mergeStrategy) => {
      const out = sanitize({ a: "1", b: "2" }, { mergeStrategy });
      expect(out).toEqual({ a: "1", b: "2" });
      expect(Array.isArray(out.a)).toBe(false);
      expect(Array.isArray(out.b)).toBe(false);
    },
  );

  it.each<MergeStrategy>(["keepFirst", "keepLast", "combine"])(
    "negative control: a single a[] spelling only expands to a scalar a (%s)",
    (mergeStrategy) => {
      const out = sanitize<Record<string, unknown>>({ "a[]": "1" }, { mergeStrategy });
      expect(out).toEqual({ a: "1" });
      expect(Array.isArray(out.a)).toBe(false);
      expect(Object.keys(out)).toEqual(["a"]);
    },
  );
});

// ---------------------------------------------------------------------------
// Middleware tier: real Express 5 apps
// ---------------------------------------------------------------------------

describe("alternate-spelling duplicates are detected by the middleware (real Express 5)", () => {
  it("default parser ?a=1&a[]=2 records the duplicate in req.queryPolluted and fires onPollutionDetected once", async () => {
    const calls: { source: string; pollutedKeys: string[] }[] = [];
    const { app, handler } = appWith(
      { onPollutionDetected: (_req, info) => calls.push(info) },
      "simple",
    );
    const res = await request(app).get("/t?a=1&a[]=2");
    expect(res.status).toBe(200);
    expect(res.body.query).toEqual({ a: "2" });
    expect(res.body.queryPolluted).toEqual({ a: ["1", "2"] });
    expect(calls).toEqual([{ source: "query", pollutedKeys: ["query.a"] }]);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  const strictMatrix: { parser: QueryParser; qs: string; polluted: string }[] = [
    { parser: "simple", qs: "a=1&a[]=2", polluted: "query.a" },
    { parser: "simple", qs: "a=1&a.=2", polluted: "query.a" },
    { parser: "simple", qs: "a=1&[a]=2", polluted: "query.a" },
    { parser: "simple", qs: "user.role=user&user[role]=admin", polluted: "query.user.role" },
    { parser: "extended", qs: "a=1&a[]=2", polluted: "query.a" },
    { parser: "extended", qs: "a=1&a.=2", polluted: "query.a" },
    { parser: "extended", qs: "a=1&[a]=2", polluted: "query.a" },
    { parser: "extended", qs: "user.role=user&user[role]=admin", polluted: "query.user.role" },
  ];

  it.each(strictMatrix)(
    "strict mode rejects ?$qs under the $parser parser with 400 and never runs the route",
    async ({ parser, qs, polluted }) => {
      const { app, handler } = appWith({ strict: true }, parser);
      const res = await request(app).get(`/t?${qs}`);
      expect(res.status).toBe(400);
      expect(res.body).toEqual({
        error: "Bad Request",
        message: "HTTP Parameter Pollution detected",
        pollutedParameters: [polluted],
        code: "HPP_DETECTED",
      });
      expect(handler).not.toHaveBeenCalled();
    },
  );

  it("urlencoded body a=1&a[]=2 (extended: false) records the duplicate in req.bodyPolluted", async () => {
    const app = express();
    app.use(express.urlencoded({ extended: false }));
    const calls: { source: string; pollutedKeys: string[] }[] = [];
    app.use(hppx({ logPollution: false, onPollutionDetected: (_req, info) => calls.push(info) }));
    app.post("/t", (req, res) => {
      res.json({ body: req.body, bodyPolluted: req.bodyPolluted ?? null });
    });
    const res = await request(app)
      .post("/t")
      .set("Content-Type", "application/x-www-form-urlencoded")
      .send("a=1&a[]=2");
    expect(res.status).toBe(200);
    expect(res.body.body).toEqual({ a: "2" });
    expect(res.body.bodyPolluted).toEqual({ a: ["1", "2"] });
    // Only the body is reported: the empty query must not produce a signal.
    expect(calls).toEqual([{ source: "body", pollutedKeys: ["body.a"] }]);
  });

  it("negative control: default parser ?a=1&b[]=2 passes strict mode untouched", async () => {
    const calls: unknown[] = [];
    const { app, handler } = appWith(
      { strict: true, onPollutionDetected: (_req, info) => calls.push(info) },
      "simple",
    );
    const res = await request(app).get("/t?a=1&b[]=2");
    expect(res.status).toBe(200);
    expect(res.body.query).toEqual({ a: "1", b: "2" });
    expect(res.body.queryPolluted).toEqual({});
    expect(calls).toEqual([]);
    expect(handler).toHaveBeenCalledTimes(1);
  });
});
