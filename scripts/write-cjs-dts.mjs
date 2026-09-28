#!/usr/bin/env node
// @ts-check
/**
 * write-cjs-dts.mjs
 *
 * Writes `dist/index.d.cts` from `dist/index.d.ts`. Runs as the second half of
 * `npm run build`, after tsup. See `scripts/_cjs-dts.mjs` for why the CommonJS
 * declarations need their own shape.
 *
 * Exit codes:
 *   0: dist/index.d.cts written
 *   1: dist/index.d.ts missing or not in the expected shape
 */

import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { toCjsDeclaration } from "./_cjs-dts.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dtsPath = path.join(root, "dist", "index.d.ts");
const dctsPath = path.join(root, "dist", "index.d.cts");

try {
  const dts = await readFile(dtsPath, "utf8");
  await writeFile(dctsPath, toCjsDeclaration(dts));
  console.log("[write-cjs-dts] wrote dist/index.d.cts (export = with a merged namespace)");
} catch (err) {
  console.error(`[write-cjs-dts] ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}
