/**
 * Compile-time smoke test for the Express Request augmentation that ships with
 * hppx. This file is not run by Jest (its `.test-d.ts` suffix is not part of
 * the default Jest match pattern); it is included in the project tsconfig's
 * `include: ["tests"]` so `npm run typecheck` (`tsc --noEmit`) verifies the
 * augmentation is visible to consumers.
 *
 * It must reference Request from express-serve-static-core / express directly,
 * import the hppx package once (so the module augmentation is applied), and
 * use each augmented field — `req.queryPolluted`, `req.bodyPolluted`,
 * `req.paramsPolluted`. Any future regression that drops the augmentation
 * from `dist/index.d.ts` (or `dist/index.d.cts`) will fail this typecheck.
 */
import type { Request } from "express-serve-static-core";
// Importing the package is what activates the `declare module` block.
import "../../src/index";

function _smokeTest(req: Request): void {
  const q: Record<string, unknown> | undefined = req.queryPolluted;
  const b: Record<string, unknown> | undefined = req.bodyPolluted;
  const p: Record<string, unknown> | undefined = req.paramsPolluted;

  // Reference each variable so noUnused* rules don't complain.
  void q;
  void b;
  void p;
}
