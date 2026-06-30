/**
 * Phase 5 — whitelist / strict / signal semantics (C11)
 *
 * These tests PIN CURRENT INTENDED BEHAVIOR. They are characterization tests,
 * not a specification that semantics must ever change to. Two foundational
 * concepts that are easy to conflate:
 *
 * 1. `whitelist` is a DATA-PRESERVATION control. After detectAndReduce
 *    collects all duplicate-parameter sites, moveWhitelistedFromPolluted puts
 *    whitelisted keys' raw arrays back into req.[source] and prunes them from
 *    req.[source]Polluted. Whitelist does NOT suppress the wire-level pollution
 *    signal — it only controls what survives into the cleaned request object.
 *
 * 2. `strict` and `logPollution` are WIRE-LEVEL DETECTION signals. They are
 *    driven by `anyPollutionDetected`, which is set from the pre-restoration
 *    `pollutedKeys` array returned by `detectAndReduce` (accumulated at
 *    src/index.ts:918–921 — after whitelist restoration at :915, but using
 *    pre-restoration data). A whitelisted key that arrives duplicated on the
 *    wire still triggers strict mode (→ HTTP 400) and logPollution (→ warning
 *    via logger/console.warn) because `anyPollutionDetected` is derived from
 *    pre-restoration data, not from the post-restoration polluted tree.
 *
 * 3. `onPollutionDetected` and req.*Polluted reflect POST-RESTORATION state.
 *    The callback fires only when req.[source]Polluted is non-empty AFTER
 *    whitelist restoration (src/index.ts:955: Object.keys(pollutedData).length
 *    > 0). When ALL polluted keys are whitelisted, the tree is {} after
 *    restoration and the callback is NOT called. When SOME (partial) are
 *    whitelisted, the callback fires — and its info.pollutedKeys reports ALL
 *    pre-restoration polluted keys for that source (both whitelisted and
 *    non-whitelisted) via src/index.ts:956–963 (allPollutedKeys.filter).
 *
 * Source lines verified: src/index.ts:873 (detectAndReduce), :915
 *   (moveWhitelistedFromPolluted), :918–921 (anyPollutionDetected
 *   accumulation), :955 (onPollutionDetected trigger condition), :971–978
 *   (strict 400 response).
 */
import express from "express";
import request from "supertest";
import hppx from "../src/index";

function buildApp(opts: Parameters<typeof hppx>[0]) {
  const app = express();
  app.use(express.urlencoded({ extended: true }));
  app.use(hppx(opts));
  app.get("/t", (req, res) =>
    res.json({
      query: req.query,
      queryPolluted: (req as any).queryPolluted ?? {},
    }),
  );
  return app;
}

// ---------------------------------------------------------------------------
// T5.1 — strict + whitelist: driven by pre-restoration data, fires regardless of whitelist
// ---------------------------------------------------------------------------

describe("T5.1 — strict + whitelist: wire-level 400 regardless of whitelist setting", () => {
  it("strict:true returns HTTP 400 even when the only duplicated key is whitelisted — pins intended behavior", async () => {
    // strict fires on the pre-restoration pollutedKeys signal (src/index.ts:971-978).
    // whitelist only controls data preservation; it does NOT suppress strict mode.
    // This is the intentional security posture: wire-level HPP is always rejected
    // in strict mode, even if the application has opted in to receiving that key
    // as an array via whitelist.
    const app = buildApp({ strict: true, whitelist: ["x"], logPollution: false });
    const res = await request(app).get("/t?x=1&x=2");
    expect(res.status).toBe(400);
    expect(res.body.code).toBe("HPP_DETECTED");
    // pollutedParameters is built from allPollutedKeys (pre-restoration)
    expect(res.body.pollutedParameters).toContain("query.x");
  });

  it("strict:false + whitelist: whitelisted key preserved as raw array; queryPolluted is {} — pins intended behavior", async () => {
    // Without strict mode, whitelist restoration runs to completion:
    // moveWhitelistedFromPolluted puts "x" back as ["1","2"] and prunes the
    // polluted tree. The route handler sees the original multi-value array.
    const app = buildApp({ strict: false, whitelist: ["x"], logPollution: false });
    const res = await request(app).get("/t?x=1&x=2");
    expect(res.status).toBe(200);
    // req.query.x restored to the pre-reduction raw array
    expect(res.body.query.x).toEqual(["1", "2"]);
    // polluted tree pruned for the whitelisted key
    expect(res.body.queryPolluted).toEqual({});
  });
});

// ---------------------------------------------------------------------------
// T5.2 — three-signal semantics under whitelist
// ---------------------------------------------------------------------------

describe("T5.2 — three-signal semantics: logPollution / onPollutionDetected / req.queryPolluted under whitelist", () => {
  it(
    "fully whitelisted dup: logPollution fires for wire-level pollution; " +
      "onPollutionDetected does NOT fire; queryPolluted is {} — pins intended behavior",
    async () => {
      // Pins current intended behavior.
      // logPollution fires because anyPollutionDetected is set from the
      // pre-restoration pollutedKeys (src/index.ts:918-921, :933-946).
      // onPollutionDetected does NOT fire because after whitelist restoration
      // req.queryPolluted is {} — the guard at src/index.ts:955 fails:
      //   Object.keys(pollutedData).length > 0  →  false  →  callback skipped.
      const logMessages: string[] = [];
      const detectedCalls: { source: string; pollutedKeys: string[] }[] = [];

      const app = express();
      app.use(express.urlencoded({ extended: true }));
      app.use(
        hppx({
          whitelist: ["a"],
          logPollution: true,
          logger: (msg) => {
            if (typeof msg === "string") logMessages.push(msg);
          },
          onPollutionDetected: (_req, info) => detectedCalls.push(info),
        }),
      );
      app.get("/t", (req, res) =>
        res.json({
          query: req.query,
          queryPolluted: (req as any).queryPolluted ?? {},
        }),
      );

      const res = await request(app).get("/t?a=1&a=2");
      expect(res.status).toBe(200);

      // logger received the wire-level pollution warning (includes "query.a")
      expect(logMessages.length).toBeGreaterThan(0);
      expect(logMessages[0]).toContain("query.a");

      // callback was NOT called: post-restoration req.queryPolluted is {} (empty)
      expect(detectedCalls.length).toBe(0);

      // whitelist restoration put the raw array back into req.query
      expect(res.body.query.a).toEqual(["1", "2"]);
      // polluted tree is empty after restoration
      expect(res.body.queryPolluted).toEqual({});
    },
  );

  it(
    "partially whitelisted: onPollutionDetected reports ALL pre-restoration polluted keys; " +
      "queryPolluted has only the non-whitelisted key — pins intended behavior",
    async () => {
      // Pins current intended behavior.
      // whitelist: ["a"] → "a" is data-preserved; "b" is not.
      // After moveWhitelistedFromPolluted: req.queryPolluted = { b: ["1","2"] }
      // (non-empty). Condition at src/index.ts:955 passes → callback fires.
      // The callback's pollutedKeys comes from allPollutedKeys.filter(...)
      // (src/index.ts:956-963), which was built from the PRE-restoration
      // pollutedKeys set — so it includes BOTH "query.a" and "query.b" even
      // though "a" has already been restored.
      const detectedCalls: { source: string; pollutedKeys: string[] }[] = [];

      const app = express();
      app.use(express.urlencoded({ extended: true }));
      app.use(
        hppx({
          whitelist: ["a"],
          logPollution: false,
          onPollutionDetected: (_req, info) => detectedCalls.push(info),
        }),
      );
      app.get("/t", (req, res) =>
        res.json({
          query: req.query,
          queryPolluted: (req as any).queryPolluted ?? {},
        }),
      );

      const res = await request(app).get("/t?a=1&a=2&b=1&b=2");
      expect(res.status).toBe(200);

      // callback fired exactly once (for the query source)
      expect(detectedCalls.length).toBe(1);
      expect(detectedCalls[0]!.source).toBe("query");
      // callback's pollutedKeys reports ALL pre-restoration polluted keys —
      // both "query.a" (whitelisted, already restored) and "query.b" (kept in tree)
      expect(detectedCalls[0]!.pollutedKeys).toContain("query.a");
      expect(detectedCalls[0]!.pollutedKeys).toContain("query.b");
      expect(detectedCalls[0]!.pollutedKeys).toHaveLength(2);

      // req.queryPolluted has only the non-whitelisted key
      expect(res.body.queryPolluted).toEqual({ b: ["1", "2"] });
      // whitelisted "a" restored as raw array; non-whitelisted "b" reduced
      expect(res.body.query.a).toEqual(["1", "2"]);
      expect(res.body.query.b).toBe("2");
    },
  );
});
