import * as fs from "fs";
import * as path from "path";
import hppx from "../src/index";

/**
 * These tests verify the logger-fallback path does not depend on `process` /
 * `process.env` being defined. In edge runtimes (Cloudflare Workers, Vercel
 * Edge, Deno without Node-compat) `process` may be `undefined` or
 * `process.env` may be a Proxy that throws. The dev/prod NODE_ENV gate that
 * previously wrapped `console.error` was removed, so the fallback now works
 * unconditionally.
 *
 * We invoke the middleware directly with a mock req/res/next instead of going
 * through supertest, because supertest/http internals reference `process` and
 * would crash when we delete it. By calling the middleware directly we can
 * narrowly assert that the hppx code path itself does not read `process`.
 */

describe("hppx - edge runtime portability (no `process`)", () => {
  const originalProcess: any = (globalThis as any).process;
  const originalConsoleError = console.error;

  afterEach(() => {
    if (typeof originalProcess !== "undefined") {
      (globalThis as any).process = originalProcess;
    }
    console.error = originalConsoleError;
  });

  test("logger-fallback path does not throw ReferenceError when `process` is undefined", () => {
    const consoleErrors: any[] = [];
    console.error = jest.fn((...args) => consoleErrors.push(args));

    const failingLogger = () => {
      throw new Error("Logger failed!");
    };

    // Build middleware while `process` is still defined (option validation
    // happens at construction time and is not the path under test).
    const middleware = hppx({
      maxDepth: 1,
      logger: failingLogger,
      logPollution: false,
    });

    // Synthesize a request that will trigger the middleware's outer catch
    // block (deep-nested key blows the maxDepth=1 limit). The catch block is
    // exactly where the previous code read `process.env.NODE_ENV`.
    const req: any = {
      query: { "a[b][c][d][e]": "value" },
      path: "/test",
      headers: {},
    };
    const res: any = { status: () => res, json: () => res };
    let nextErr: unknown = null;
    const next = (err?: unknown) => {
      nextErr = err;
    };

    // Now simulate an edge runtime by deleting `globalThis.process` for the
    // duration of the middleware call. The hppx logger-fallback path must NOT
    // throw a ReferenceError trying to read `process.env.NODE_ENV`.
    delete (globalThis as any).process;

    let threw: unknown = null;
    try {
      middleware(req, res, next);
    } catch (err) {
      threw = err;
    } finally {
      // Restore `process` before any assertions so the test framework can
      // continue to function normally.
      (globalThis as any).process = originalProcess;
    }

    expect(threw).toBeNull();
    // The middleware should have caught the deep-nesting error internally,
    // hit the failing logger, fallen back to console.error, and called next(error).
    expect(nextErr).toBeInstanceOf(Error);
    const hppxErrors = consoleErrors.filter((args) =>
      args.some((arg: any) => typeof arg === "string" && arg.includes("[hppx]")),
    );
    expect(hppxErrors.length).toBeGreaterThan(0);
  });

  test("source no longer guards logger fallback by NODE_ENV", () => {
    // Defense-in-depth: assert the dev/prod gate is gone from the source.
    // The fallback should ALWAYS log on logger failure, since logger failure
    // is a developer bug regardless of NODE_ENV.
    const src = fs.readFileSync(path.join(__dirname, "..", "src", "index.ts"), "utf8");
    expect(src).not.toMatch(/process\.env\.NODE_ENV\s*!==\s*["']production["']/);
  });
});
