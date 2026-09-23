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

// ---------------------------------------------------------------------------
// Safety invariants of the collision-aware expansion path
// ---------------------------------------------------------------------------

describe("collision merging never mutates caller-owned data (sanitize)", () => {
  it("a caller array that collides with two more spellings is copied, never appended to", () => {
    const arr = ["1", "2"];
    const input: Record<string, unknown> = { a: arr, "a[]": "3", "a.": "4" };
    const out = sanitize(input, { mergeStrategy: "combine" });
    expect(out).toEqual({ a: ["1", "2", "3", "4"] });
    // The caller's array is untouched: same reference in the input, same contents, same length.
    expect(input.a).toBe(arr);
    expect(arr).toEqual(["1", "2"]);
    expect(arr).toHaveLength(2);
  });

  it("a caller array arriving as the second spelling is flattened into a new array, never aliased", () => {
    const incoming = ["2", "3"];
    const input: Record<string, unknown> = { a: "1", "a[]": incoming, "a.": "4" };
    const out = sanitize(input, { mergeStrategy: "combine" });
    expect(out).toEqual({ a: ["1", "2", "3", "4"] });
    expect(incoming).toEqual(["2", "3"]);
    expect(incoming).toHaveLength(2);
  });

  it("a caller object that a dotted spelling writes into is expanded into a copy first", () => {
    const inner = { c: "2" };
    const input: Record<string, unknown> = { a: inner, "a.b": "1" };
    const out = sanitize(input, { mergeStrategy: "combine" });
    expect(out).toEqual({ a: { c: "2", b: "1" } });
    expect(input.a).toBe(inner);
    expect(Object.prototype.hasOwnProperty.call(inner, "b")).toBe(false);
    expect(inner).toEqual({ c: "2" });
  });

  it("a caller object merged into an earlier dotted spelling is left untouched", () => {
    const inner = { c: "2" };
    const input: Record<string, unknown> = { "a.b": "1", a: inner };
    const out = sanitize(input, { mergeStrategy: "combine" });
    expect(out).toEqual({ a: { b: "1", c: "2" } });
    expect(Object.keys(inner)).toEqual(["c"]);
  });
});

describe("the collision path is prototype-safe with outputs identical to the pre-merge expansion (sanitize)", () => {
  // If a regression ever did write through a dangerous key, keep the damage out
  // of the remaining tests in this file.
  afterEach(() => {
    delete (Object.prototype as Record<string, unknown>).polluted;
  });

  const cases: {
    name: string;
    input: Record<string, unknown>;
    expected: Record<string, unknown>;
  }[] = [
    {
      name: "scalar a then a.__proto__ leaf",
      input: { a: "1", "a.__proto__": "x" },
      expected: { a: {} },
    },
    {
      name: "a.__proto__ as an intermediate segment",
      input: { "a.__proto__.polluted": "x" },
      expected: { a: {} },
    },
    {
      name: "bracketed __proto__ intermediate under an existing object",
      input: { a: { x: "1" }, "a[__proto__][polluted]": "yes" },
      expected: { a: { x: "1" } },
    },
    {
      name: "constructor.prototype chain",
      input: { "constructor.prototype.polluted": "x" },
      expected: {},
    },
    {
      name: "object-valued a.__proto__ leaf",
      input: { "a.__proto__": { polluted: "yes" } },
      expected: { a: {} },
    },
    {
      name: "a.constructor leaf dropped while two spellings of a merge",
      input: { "a.b": "1", a: { c: "2" }, "a.constructor": "z" },
      expected: { a: { b: "1", c: "2" } },
    },
  ];

  it.each(cases)("$name", ({ input, expected }) => {
    const out = sanitize<Record<string, unknown>>(input, { mergeStrategy: "combine" });
    expect(out).toEqual(expected);
    expect(Object.keys(out)).toEqual(Object.keys(expected));
    if (Object.prototype.hasOwnProperty.call(expected, "a")) {
      expect(Object.getPrototypeOf(out.a)).toBe(Object.prototype);
      expect(Object.keys(out.a as object)).toEqual(Object.keys(expected.a as object));
    }
    expect((out.a as any)?.polluted).toBeUndefined();
    expect(({} as any).polluted).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(Object.prototype, "polluted")).toBe(false);
  });
});

describe("only own properties count as collisions, observed through combine (sanitize)", () => {
  it("a lone toString key is a plain write, not a collision with Object.prototype.toString", () => {
    const out = sanitize<Record<string, unknown>>({ toString: "1" }, { mergeStrategy: "combine" });
    expect(out).toEqual({ toString: "1" });
    expect(typeof out.toString).toBe("string");
  });

  it("two spellings of toString combine only their own values", () => {
    const out = sanitize<Record<string, unknown>>(
      { toString: "1", "toString[]": "2" },
      { mergeStrategy: "combine" },
    );
    expect(out).toEqual({ toString: ["1", "2"] });
    expect(Object.keys(out)).toEqual(["toString"]);
  });

  it("an own hasOwnProperty key does not break collision checks on later keys", () => {
    const out = sanitize<Record<string, unknown>>(
      { hasOwnProperty: "x", a: "1", "a.": "2" },
      { mergeStrategy: "combine" },
    );
    expect(out).toEqual({ hasOwnProperty: "x", a: ["1", "2"] });
    expect(Object.keys(out)).toEqual(["hasOwnProperty", "a"]);
  });
});

// ---------------------------------------------------------------------------
// Interplay with strategies, whitelists, limits and stacked instances
// ---------------------------------------------------------------------------

describe("combined duplicates interact with whitelists, strategies and limits as documented", () => {
  it("an exact whitelist restores the combined array while logPollution still reports the wire-level duplicate", async () => {
    const logs: unknown[] = [];
    const calls: unknown[] = [];
    const { app, handler } = appWith(
      {
        whitelist: ["a"],
        logPollution: true,
        logger: (msg) => logs.push(msg),
        onPollutionDetected: (_req, info) => calls.push(info),
      },
      "simple",
    );
    const res = await request(app).get("/t?a=1&a[]=2");
    expect(res.status).toBe(200);
    expect(res.body.query).toEqual({ a: ["1", "2"] });
    expect(res.body.queryPolluted).toEqual({});
    expect(logs).toEqual([
      "[hppx] HTTP Parameter Pollution detected - 1 parameter(s) affected: query.a",
    ]);
    // Fully whitelisted: the post-restoration tree is empty, so the callback stays silent.
    expect(calls).toEqual([]);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it.each([
    { kind: "nested exact", whitelist: ["user.role"] },
    { kind: "leaf", whitelist: ["role"] },
    { kind: "prefix", whitelist: ["user"] },
  ])(
    "a $kind whitelist restores the combined user.role spellings (extended parser)",
    async ({ whitelist }) => {
      const { app } = appWith({ whitelist }, "extended");
      const res = await request(app).get("/t?user.role=user&user[role]=admin");
      expect(res.status).toBe(200);
      expect(res.body.query).toEqual({ user: { role: ["user", "admin"] } });
      expect(res.body.queryPolluted).toEqual({});
    },
  );

  it("a non-matching whitelist leaves the combined user.role duplicate reduced and reported", async () => {
    const { app } = appWith({ whitelist: ["other"] }, "extended");
    const res = await request(app).get("/t?user.role=user&user[role]=admin");
    expect(res.status).toBe(200);
    expect(res.body.query).toEqual({ user: { role: "admin" } });
    expect(res.body.queryPolluted).toEqual({ user: { role: ["user", "admin"] } });
  });

  it.each<[MergeStrategy, unknown]>([
    ["combine", ["1", "3", "2"]],
    ["keepFirst", "1"],
    ["keepLast", "2"],
  ])(
    "default parser ?a=1&b=x&a[]=2&a=3 combines in parser key order, not wire order (%s)",
    async (mergeStrategy, expected) => {
      const { app } = appWith({ mergeStrategy }, "simple");
      const res = await request(app).get("/t?a=1&b=x&a[]=2&a=3");
      expect(res.status).toBe(200);
      expect(res.body.query).toEqual({ a: expected, b: "x" });
      expect(res.body.queryPolluted).toEqual({ a: ["1", "3", "2"] });
    },
  );

  it("maxArrayLength truncates a combined array like any other array", () => {
    const out = sanitize<Record<string, unknown>>(
      { a: "1", "a.": "2", "a[]": "3" },
      { mergeStrategy: "combine", maxArrayLength: 2 },
    );
    expect(out).toEqual({ a: ["1", "2"] });
    expect(out.a).toHaveLength(2);
    expect(out.a).not.toContain("3");
  });

  it("two spellings of user.role are reported once, under the normalized dotted path", async () => {
    const calls: { source: string; pollutedKeys: string[] }[] = [];
    const { app } = appWith({ onPollutionDetected: (_req, info) => calls.push(info) }, "extended");
    const res = await request(app).get("/t?user.role=a&user[role]=b");
    expect(res.status).toBe(200);
    expect(calls).toEqual([{ source: "query", pollutedKeys: ["query.user.role"] }]);
    expect(res.body.query).toEqual({ user: { role: "b" } });
    expect(Object.keys(res.body.query)).toEqual(["user"]);
  });

  it("a router-level whitelist restores a combined array already reduced by a global instance", async () => {
    const app = express();
    app.set("query parser", "simple");
    app.use(hppx({ logPollution: false }));
    const router = express.Router();
    router.use(hppx({ logPollution: false, whitelist: ["a"] }));
    router.get("/t", (req, res) => {
      res.json({ query: req.query, queryPolluted: req.queryPolluted ?? null });
    });
    app.use("/r", router);
    const res = await request(app).get("/r/t?a=1&a[]=2");
    expect(res.status).toBe(200);
    expect(res.body.query).toEqual({ a: ["1", "2"] });
    expect(res.body.queryPolluted).toEqual({});
  });

  it("a stacked instance reports only the sources it detected itself, never re-reporting an earlier instance's source", async () => {
    const globalCalls: { source: string; pollutedKeys: string[] }[] = [];
    const routerCalls: { source: string; pollutedKeys: string[] }[] = [];
    const app = express();
    app.set("query parser", "simple");
    app.use(express.urlencoded({ extended: false }));
    app.use(
      hppx({
        logPollution: false,
        sources: ["query"],
        onPollutionDetected: (_req, info) => globalCalls.push(info),
      }),
    );
    const router = express.Router();
    router.use(
      hppx({ logPollution: false, onPollutionDetected: (_req, info) => routerCalls.push(info) }),
    );
    router.post("/t", (req, res) => {
      res.json({
        query: req.query,
        body: req.body,
        queryPolluted: req.queryPolluted ?? null,
        bodyPolluted: req.bodyPolluted ?? null,
      });
    });
    app.use("/r", router);
    const res = await request(app)
      .post("/r/t?a=1&a[]=2")
      .set("Content-Type", "application/x-www-form-urlencoded")
      .send("b=1&b.=2");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      query: { a: "2" },
      body: { b: "2" },
      queryPolluted: { a: ["1", "2"] },
      bodyPolluted: { b: ["1", "2"] },
    });
    expect(globalCalls).toEqual([{ source: "query", pollutedKeys: ["query.a"] }]);
    // The router instance saw the query only as already processed: it must not
    // report it again (and never with an empty key list).
    expect(routerCalls).toEqual([{ source: "body", pollutedKeys: ["body.b"] }]);
  });
});
