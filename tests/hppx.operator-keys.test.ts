import express from "express";
import request from "supertest";
import hppx, { sanitize, type HppxOptions } from "../src/index";

/**
 * Key expansion turns dotted and bracketed keys into nested objects. It must
 * never create a key that starts with `$`: MongoDB (and similar stores) read
 * such keys as query operators, and Express 5's default query parser delivers
 * `?password[$ne]=x` as the harmless flat key "password[$ne]". A key whose
 * expansion would contain a `$` segment is dropped before anything is written.
 * Keys the input already contained (a flat `$top`, or `{ $lt: 2 }` nested by
 * the `extended` parser or a JSON body) are not hppx's creation and pass
 * through; validating input is still the application's job.
 */

function allKeys(value: unknown, out: string[] = []): string[] {
  if (Array.isArray(value)) {
    for (const item of value) allKeys(item, out);
  } else if (value !== null && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      out.push(key);
      allKeys(item, out);
    }
  }
  return out;
}

const hasDollarKey = (value: unknown): boolean => allKeys(value).some((k) => k.startsWith("$"));

function appWith(options: HppxOptions = {}, queryParser: "simple" | "extended" = "simple") {
  const app = express();
  app.set("query parser", queryParser);
  app.use(express.urlencoded({ extended: false }));
  app.use(hppx({ logPollution: false, ...options }));
  app.all("/", (req, res) => {
    res.json({
      query: req.query,
      queryPolluted: req.queryPolluted ?? null,
      body: req.body ?? null,
      bodyPolluted: req.bodyPolluted ?? null,
    });
  });
  return app;
}

describe("key expansion never creates `$`-prefixed keys", () => {
  describe("sanitize()", () => {
    it.each([
      ["bracketed", "password[$ne]"],
      ["dotted", "password.$ne"],
      ["nested bracketed", "user[role][$in]"],
      ["mixed-spelling", "user.role[$gt]"],
      ["leading operator segment", "$or[0][a]"],
      ["trailing-dot", "$where."],
      ["bare `$` segment", "a[$]"],
      ["leading-bracket", "[$ne]"],
    ])("drops a %s key (%s) entirely and keeps its siblings", (_label, key) => {
      const out = sanitize({ [key]: "x", keep: "1" });

      expect(out).toEqual({ keep: "1" });
      expect(hasDollarKey(out)).toBe(false);
    });

    it("drops only the operator spelling of a key and keeps the other spellings", () => {
      expect(sanitize({ "a[b]": "1", "a[$gt]": "2" })).toEqual({ a: { b: "1" } });
    });

    it("drops a composite operator key inside a nested object", () => {
      expect(sanitize({ user: { "role[$in]": "admin" } })).toEqual({ user: {} });
      expect(sanitize({ user: { "role[$in]": "admin", name: "n" } })).toEqual({
        user: { name: "n" },
      });
    });

    it("leaves flat `$`-prefixed keys alone, because expansion did not create them", () => {
      const input = { $top: "10", $filter: "name eq 'x'", $where: "1" };

      expect(sanitize(input)).toEqual({ $top: "10", $filter: "name eq 'x'", $where: "1" });
    });

    it("drops the bracketed spelling of a flat `$` key instead of combining the two", () => {
      expect(sanitize({ $top: "1", "$top[]": "2" })).toEqual({ $top: "1" });
    });

    it("leaves operators the input already nested untouched (validation is the app's job)", () => {
      expect(sanitize({ b: { $lt: 2 } })).toEqual({ b: { $lt: 2 } });
      expect(sanitize({ a: { $ne: 1 }, "a.b": 2 })).toEqual({ a: { $ne: 1, b: 2 } });
    });

    it("treats only a leading `$` in a segment as an operator", () => {
      expect(sanitize({ "a[b$]": "1", "c.d$e": "2" })).toEqual({ a: { b$: "1" }, c: { d$e: "2" } });
    });

    it("drops the key before expanding its value, so a discarded subtree cannot trip maxDepth", () => {
      let deep: Record<string, unknown> = { leaf: "x" };
      for (let i = 0; i < 10; i++) deep = { n: deep };

      expect(sanitize({ "a[$ne]": deep, keep: "1" }, { maxDepth: 5 })).toEqual({ keep: "1" });
      // Control: the same subtree under a kept key does exceed the limit.
      expect(() => sanitize({ a: deep }, { maxDepth: 5 })).toThrow(
        "Maximum object depth (5) exceeded",
      );
    });
  });

  describe("middleware on Express 5", () => {
    it.each([["password[$ne]=x"], ["password.$ne=x"]])(
      "drops ?%s under the default simple parser",
      async (query) => {
        const res = await request(appWith()).get(`/?${query}&name=a`);

        expect(res.status).toBe(200);
        expect(res.body.query).toEqual({ name: "a" });
        expect(res.body.queryPolluted).toEqual({});
      },
    );

    it("drops a dotted operator key under the extended parser (qs does not split dots)", async () => {
      const res = await request(appWith({}, "extended")).get("/?password.$ne=x&name=a");

      expect(res.body.query).toEqual({ name: "a" });
    });

    it("drops the literal `[$ne]` key qs leaves behind past its depth limit", async () => {
      const res = await request(appWith({}, "extended")).get("/?a[b][c][d][e][f][$ne]=1");

      expect(res.body.query).toEqual({ a: { b: { c: { d: { e: { f: {} } } } } } });
      expect(hasDollarKey(res.body.query)).toBe(false);
    });

    it("passes through an operator the extended parser nested itself (documented scope)", async () => {
      const res = await request(appWith({}, "extended")).get("/?password[$ne]=x");

      expect(res.status).toBe(200);
      expect(res.body.query).toEqual({ password: { $ne: "x" } });
      expect(res.body.queryPolluted).toEqual({});
    });

    it("drops an operator key in a urlencoded body", async () => {
      const res = await request(appWith()).post("/").type("form").send("password[$ne]=x&name=a");

      expect(res.body.body).toEqual({ name: "a" });
      expect(res.body.bodyPolluted).toEqual({});
    });

    it("does not report a dropped key as pollution", async () => {
      const onPollutionDetected = jest.fn();
      const res = await request(appWith({ onPollutionDetected })).get(
        "/?password[$ne]=a&password[$ne]=b&$top=1&$top[]=2",
      );

      expect(res.body.query).toEqual({ $top: "1" });
      expect(res.body.queryPolluted).toEqual({});
      expect(onPollutionDetected).not.toHaveBeenCalled();
    });

    it("strict mode: a dropped key alone is not rejected", async () => {
      const res = await request(appWith({ strict: true })).get("/?password[$ne]=x");

      expect(res.status).toBe(200);
      expect(res.body.query).toEqual({});
    });

    it("strict mode: an operator spelling can no longer hide a duplicate", async () => {
      const res = await request(appWith({ strict: true })).get("/?a=1&a=2&a[$ne]=3");

      expect(res.status).toBe(400);
      expect(res.body).toEqual({
        error: "Bad Request",
        message: "HTTP Parameter Pollution detected",
        pollutedParameters: ["query.a"],
        code: "HPP_DETECTED",
      });
    });
  });
});
