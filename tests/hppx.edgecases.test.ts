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

  test("sanitize validates options like hppx middleware", () => {
    expect(() => sanitize({}, { maxDepth: -1 })).toThrow(TypeError);
    expect(() => sanitize({}, { maxDepth: 0 })).toThrow(TypeError);
    expect(() => sanitize({}, { maxDepth: 1000 })).toThrow(TypeError);
    expect(() => sanitize({}, { maxKeys: -1 })).toThrow(TypeError);
    expect(() => sanitize({}, { maxArrayLength: 0 })).toThrow(TypeError);
    expect(() => sanitize({}, { maxKeyLength: 2000 })).toThrow(TypeError);
    expect(() => sanitize({}, { mergeStrategy: "invalid" as any })).toThrow(TypeError);
  });

  test("sanitize accepts valid options without throwing", () => {
    expect(() => sanitize({}, { maxDepth: 10 })).not.toThrow();
    expect(() => sanitize({}, { maxKeys: 100 })).not.toThrow();
    expect(() => sanitize({}, { maxArrayLength: 50 })).not.toThrow();
    expect(() => sanitize({}, { maxKeyLength: 100 })).not.toThrow();
    expect(() => sanitize({}, { mergeStrategy: "keepFirst" })).not.toThrow();
  });
});

describe("preserveNull behavior", () => {
  test("preserveNull: false strips null values to undefined", () => {
    const out = sanitize({ a: null, b: "ok" } as any, {
      preserveNull: false,
    });
    expect(out.a).toBeUndefined();
    expect(out.b).toBe("ok");
  });

  test("preserveNull: false strips nulls from array reduction", () => {
    const out = sanitize({ a: ["x", null as any] } as any, {
      mergeStrategy: "keepLast",
      preserveNull: false,
    });
    // keepLast picks null, then preserveNull: false converts to undefined
    expect(out.a).toBeUndefined();
  });

  test("preserveNull: false with nested objects", () => {
    const out = sanitize({ user: { name: null, age: 30 } } as any, {
      preserveNull: false,
    });
    expect(out.user.name).toBeUndefined();
    expect(out.user.age).toBe(30);
  });

  test("preserveNull: true (default) preserves null values", () => {
    const out = sanitize({ a: null, b: "ok" } as any, {
      preserveNull: true,
    });
    expect(out.a).toBeNull();
    expect(out.b).toBe("ok");
  });

  test("preserveNull: false in middleware integration", async () => {
    const app = express();
    app.use(express.json());
    app.use(hppx({ checkBodyContentType: "any", preserveNull: false, logPollution: false }));
    app.post("/test", (req, res) => res.json({ body: req.body }));
    const res = await request(app)
      .post("/test")
      .set("content-type", "application/json")
      .send({ a: null, b: "ok" });
    expect(res.status).toBe(200);
    // null should be stripped (converted to undefined, which is omitted from JSON)
    expect(res.body.body.a).toBeUndefined();
    expect(res.body.body.b).toBe("ok");
  });
});

describe("empty-array characterization — current intended behavior (C2)", () => {
  // Pins: keepLast/keepFirst on an empty array reduces to undefined because mergeValues
  // selects values[last]/values[0] from an empty array (both undefined). combine reduces
  // to [] because the accumulator starts empty and has nothing to push. Pollution IS
  // recorded in all three cases — the empty array is treated as a duplicate-parameter
  // event at the key level. Do NOT change mergeValues or the pollution recording logic.

  test("keepLast: sanitize({x:[]}) -> cleaned.x is undefined — pins current behavior", () => {
    const result = sanitize({ x: [] } as any, { mergeStrategy: "keepLast" });
    expect(result).toEqual({ x: undefined });
  });

  test("keepFirst: sanitize({x:[]}) -> cleaned.x is undefined — pins current behavior", () => {
    const result = sanitize({ x: [] } as any, { mergeStrategy: "keepFirst" });
    expect(result).toEqual({ x: undefined });
  });

  test("combine: sanitize({x:[]}) -> cleaned.x is [] — pins current behavior", () => {
    const result = sanitize({ x: [] } as any, { mergeStrategy: "combine" });
    expect(result).toEqual({ x: [] });
  });

  test("middleware: empty-array body key is recorded in bodyPolluted and fires onPollutionDetected", async () => {
    // Pins: even with no actual duplicate scalar values, an empty array at a body key
    // is treated as pollution. bodyPolluted captures the original [], and
    // onPollutionDetected fires. Do NOT suppress the pollution signal for empty arrays.
    const calls: { source: string; pollutedKeys: string[] }[] = [];
    const app = express();
    app.use(express.json());
    app.use(
      hppx({
        sources: ["body"],
        checkBodyContentType: "any",
        mergeStrategy: "keepLast",
        logPollution: false,
        onPollutionDetected: (_req, info) => calls.push(info),
      }),
    );
    app.post("/test", (req, res) => res.json({ bodyPolluted: req.bodyPolluted }));
    const res = await request(app)
      .post("/test")
      .set("content-type", "application/json")
      .send({ x: [] });
    // bodyPolluted must capture the original empty array
    expect(res.body.bodyPolluted).toEqual({ x: [] });
    // onPollutionDetected must fire once for the body source
    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual({ source: "body", pollutedKeys: ["body.x"] });
  });
});

describe("scalar–dotted key collision — current intended behavior (C3)", () => {
  // Pins: expandObjectPaths processes keys in JavaScript object insertion order.
  // When a plain key and a dotted key share a path prefix ('a' and 'a.b'),
  // the LAST-processed key wins by overwriting. This is order-dependent and lossy
  // by design — hppx is an HTTP pollution guard, not a key-path merger. Do NOT
  // change expandObjectPaths or setIn to alter this ordering.

  test("collision {a:1,'a.b':2} -> {a:{b:2}}: dotted key wins when processed last — pins current behavior", () => {
    // 'a.b' is inserted after 'a'; expandObjectPaths expands it last and setIn
    // overwrites result.a (scalar 1) with {b:2} because setIn replaces any
    // non-plain-object at an intermediate path segment with a fresh {}.
    const result = sanitize({ a: 1, "a.b": 2 } as any);
    expect(result).toEqual({ a: { b: 2 } });
  });

  test("collision reversed {'a.b':2,a:1} -> {a:1}: plain key wins when processed last — pins current behavior", () => {
    // 'a' is processed after 'a.b' expansion; plain assignment overwrites the nested
    // object {b:2} with the scalar 1 because plain (non-dotted) keys bypass setIn.
    const result = sanitize({ "a.b": 2, a: 1 } as any);
    expect(result).toEqual({ a: 1 });
  });
});

describe("combine + whitelist interaction — current intended behavior (C4)", () => {
  // Pins: detectAndReduce stores the original (pre-combine) cloned array in the polluted tree
  // (src/index.ts:592), then mergeValues flattens it for the cleaned output. Afterwards,
  // moveWhitelistedFromPolluted restores the raw polluted-tree entry into cleaned for whitelisted
  // keys (src/index.ts:487-516). This means whitelisted keys preserve the un-flattened array —
  // the data-preservation contract documented in the README as "Keys allowed to remain as arrays".
  // Do NOT alter this two-pass flow (detectAndReduce → moveWhitelistedFromPolluted).

  test("combine + whitelist: whitelisted key restored as raw un-flattened array — pins current behavior", () => {
    // x = [["1"],["2"]]: combine would flatten to ["1","2"], but whitelist ["x"] causes
    // moveWhitelistedFromPolluted to restore the polluted-tree entry [["1"],["2"]] (the
    // original cloned nested array) back into cleaned, overwriting the combined output.
    const result = sanitize({ x: [["1"], ["2"]] } as any, {
      mergeStrategy: "combine",
      whitelist: ["x"],
    });
    expect(result.x).toEqual([["1"], ["2"]]);
  });

  test("combine + whitelist: non-whitelisted key still gets combine-flattened output — pins current behavior", () => {
    // x (whitelisted) is restored as the raw nested array; y (not whitelisted) remains as the
    // combine-flattened output ["a","b"] — demonstrating both behaviors in one call.
    const result = sanitize({ x: [["1"], ["2"]], y: [["a"], ["b"]] } as any, {
      mergeStrategy: "combine",
      whitelist: ["x"],
    });
    expect(result.x).toEqual([["1"], ["2"]]); // whitelisted: raw un-flattened restored
    expect(result.y).toEqual(["a", "b"]); // non-whitelisted: combine-flattened
  });

  test("combine + whitelist middleware: req.queryPolluted pruned empty for whitelisted key — pins current behavior", async () => {
    // Pins: after moveWhitelistedFromPolluted restores x from polluted tree, pollutedTree.x is
    // deleted (src/index.ts:511), so req.queryPolluted becomes {} even though pollution was
    // detected. The query value is preserved as the raw array from the polluted tree.
    const app = express();
    app.use(
      hppx({
        sources: ["query"],
        mergeStrategy: "combine",
        whitelist: ["x"],
        logPollution: false,
      }),
    );
    app.get("/test", (req, res) =>
      res.json({ query: req.query, queryPolluted: req.queryPolluted }),
    );
    const res = await request(app).get("/test?x=1&x=2");
    expect(res.status).toBe(200);
    // x restored from polluted tree (raw array ["1","2"] — combine output equals polluted entry
    // for flat-string query params, but the restoration path is the same).
    expect(res.body.query.x).toEqual(["1", "2"]);
    // Polluted tree pruned of x after whitelist restoration — current intended behavior.
    expect(res.body.queryPolluted).toEqual({});
  });
});
