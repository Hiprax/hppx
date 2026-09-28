import express from "express";
import request from "supertest";
import hppx, { sanitize, type HppxOptions } from "../src/index";

/**
 * `trimValues` trims every string hppx writes to the sanitized output: direct
 * values, elements of arrays kept by `combine`, and whitelisted arrays restored
 * from the polluted tree (strings nested in them included). The polluted tree
 * (`req.queryPolluted`, ...) keeps the original values. With stacked
 * instances, values a later instance restores follow the first instance's
 * `trimValues`, which is the instance that processed the source.
 */

const QUERY = "/?s=%20a%20&w=%20b%20&w=%20c%20&k=%20d%20&k=%20e%20";

function respond(req: express.Request, res: express.Response) {
  res.json({ query: req.query, queryPolluted: req.queryPolluted ?? null });
}

function appWith(...stack: HppxOptions[]) {
  const app = express();
  for (const options of stack) app.use(hppx({ logPollution: false, ...options }));
  app.get("/", respond);
  return app;
}

describe("trimValues trims strings inside arrays", () => {
  describe("sanitize()", () => {
    it("trims the elements of a combined array, including nested arrays", () => {
      expect(
        sanitize({ k: [" d ", " e "] }, { trimValues: true, mergeStrategy: "combine" }),
      ).toEqual({ k: ["d", "e"] });
      expect(
        sanitize({ a: [[" x "], " y "] }, { trimValues: true, mergeStrategy: "combine" }),
      ).toEqual({ a: ["x", "y"] });
    });

    it("trims a whitelisted array of strings", () => {
      expect(
        sanitize({ w: [" b ", " c "], s: " a " }, { trimValues: true, whitelist: ["w"] }),
      ).toEqual({ w: ["b", "c"], s: "a" });
    });

    it("trims strings nested in a whitelisted array of objects", () => {
      const out = sanitize(
        { items: [{ n: " a " }, { n: " b ", tags: [" t "] }] },
        { trimValues: true, whitelist: ["items"] },
      );

      expect(out).toEqual({ items: [{ n: "a" }, { n: "b", tags: ["t"] }] });
    });

    it("keeps the nesting of a whitelisted array under combine while trimming it", () => {
      expect(
        sanitize(
          { w: [[" 1 "], [" 2 "]] },
          { trimValues: true, mergeStrategy: "combine", whitelist: ["w"] },
        ),
      ).toEqual({ w: [["1"], ["2"]] });
    });

    it("leaves values that are not strings untouched", () => {
      expect(
        sanitize({ w: [1, null, true, " x ", { n: 2 }] }, { trimValues: true, whitelist: ["w"] }),
      ).toEqual({ w: [1, null, true, "x", { n: 2 }] });
      expect(
        sanitize({ k: [1, " a ", false] }, { trimValues: true, mergeStrategy: "combine" }),
      ).toEqual({ k: [1, "a", false] });
    });

    it("trims nothing when trimValues is off (the default)", () => {
      expect(
        sanitize(
          { w: [" b "], k: [" d ", " e "], s: " a " },
          { whitelist: ["w"], mergeStrategy: "combine" },
        ),
      ).toEqual({ w: [" b "], k: [" d ", " e "], s: " a " });
    });
  });

  describe("middleware", () => {
    it("trims the sanitized query while req.queryPolluted keeps the original values", async () => {
      const res = await request(appWith({ trimValues: true, whitelist: ["w"] })).get(QUERY);

      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        query: { s: "a", w: ["b", "c"], k: "e" },
        queryPolluted: { k: [" d ", " e "] },
      });
    });

    it("stacked: a later instance restores values trimmed when the first instance trims", async () => {
      const res = await request(appWith({ trimValues: true }, { whitelist: ["w"] })).get(QUERY);

      expect(res.body).toEqual({
        query: { s: "a", w: ["b", "c"], k: "e" },
        queryPolluted: { k: [" d ", " e "] },
      });
    });

    it("stacked: a later instance's own trimValues is ignored, as documented", async () => {
      const res = await request(appWith({}, { whitelist: ["w"], trimValues: true })).get(QUERY);

      expect(res.body).toEqual({
        query: { s: " a ", w: [" b ", " c "], k: " e " },
        queryPolluted: { k: [" d ", " e "] },
      });
    });

    it("records the first instance's trimValues in a hidden, read-only flag, only when it is on", () => {
      const run = (options: HppxOptions) => {
        const req: any = { headers: {}, query: { a: " x " } };
        const next = jest.fn();
        hppx({ logPollution: false, ...options })(req, {}, next);
        expect(next).toHaveBeenCalledWith();
        return req;
      };

      const trimmed = run({ trimValues: true });
      expect(trimmed.query).toEqual({ a: "x" });
      expect(Object.getOwnPropertyDescriptor(trimmed, "__hppxTrimValues_query")).toEqual({
        value: true,
        writable: false,
        enumerable: false,
        configurable: false,
      });
      expect(Object.keys(trimmed)).not.toContain("__hppxTrimValues_query");
      expect(JSON.stringify(trimmed)).not.toContain("__hppxTrimValues");

      const untouched = run({});
      expect(untouched.query).toEqual({ a: " x " });
      expect(Object.prototype.hasOwnProperty.call(untouched, "__hppxTrimValues_query")).toBe(false);
    });

    it("a polluted tree tampered with between instances cannot inject a prototype through the trimmed copy", async () => {
      const app = express();
      app.use(hppx({ trimValues: true, logPollution: false }));
      app.use((req, _res, next) => {
        (req.queryPolluted as Record<string, unknown>).w = [
          JSON.parse('{"__proto__": {"injected": "yes"}, "n": " a "}'),
        ];
        next();
      });
      app.use(hppx({ whitelist: ["w"], logPollution: false }));
      app.get("/", (req, res) => {
        const restored = (req.query.w as unknown as Record<string, unknown>[])[0]!;
        res.json({
          ownProto: Object.prototype.hasOwnProperty.call(restored, "__proto__"),
          protoIsObjectPrototype: Object.getPrototypeOf(restored) === Object.prototype,
          injected: (restored as { injected?: unknown }).injected ?? null,
          globalInjected: ({} as { injected?: unknown }).injected ?? null,
          restored,
        });
      });

      const res = await request(app).get("/?w=1");

      expect(res.body).toEqual({
        ownProto: false,
        protoIsObjectPrototype: true,
        injected: null,
        globalInjected: null,
        restored: { n: "a" },
      });
    });
  });
});
