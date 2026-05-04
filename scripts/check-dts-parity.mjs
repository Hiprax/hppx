#!/usr/bin/env node
// @ts-check
/**
 * check-dts-parity.mjs
 *
 * Verifies that the published ESM (`dist/index.d.ts`) and CommonJS
 * (`dist/index.d.cts`) type declaration files expose the same set of public
 * symbols.
 *
 * Why: tsup auto-generates both files from `src/index.ts`. When new exports
 * are added to `src/index.ts`, the two emitted variants can drift apart
 * unnoticed (different naming/aliasing across module formats, missed
 * re-exports). This script is wired into the `prepare` lifecycle so that
 * any drift fails the build before publish.
 *
 * Symbol extraction is intentionally simple, regex-based, and tolerant of the
 * various forms tsup emits (declare function/const/class, interface, type,
 * default export markers, `export = X` for CJS, and namespace re-exports).
 *
 * Exit codes:
 *   0 — files match
 *   1 — files diverge or could not be read
 */

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const dtsPath = path.join(root, "dist", "index.d.ts");
const dctsPath = path.join(root, "dist", "index.d.cts");

/**
 * Returns the set of exported public symbol names declared/exported by a `.d.ts`
 * or `.d.cts` source. The `default` export is normalized to the literal name
 * `"default"` regardless of whether the form is `export = name`, `export
 * default name`, or `name as default` in a re-export list.
 *
 * @param {string} source
 * @returns {Set<string>}
 */
function extractExportedSymbols(source) {
  const symbols = new Set();

  // Strip block comments so symbols mentioned in JSDoc don't pollute results.
  const stripped = source.replace(/\/\*[\s\S]*?\*\//g, "");

  // 1. Top-level `export { A, B as C, default as D }` lists. tsup emits these
  //    as the primary surface for `dist/index.d.ts`. Multiline entries are
  //    common, so the inner content runs across newlines.
  const exportListRe = /export\s*\{([^}]*)\}/g;
  for (const match of stripped.matchAll(exportListRe)) {
    const body = match[1] ?? "";
    // Each entry: "name", "name as alias", "type Name", "type Name as Alias",
    // "Name as default" (the special export-as-default form). We always record
    // the alias (the "outside" name) since that is what consumers see.
    for (const rawEntry of body.split(",")) {
      const entry = rawEntry.trim();
      if (!entry) continue;
      // Optional leading "type " modifier.
      const noType = entry.replace(/^type\s+/, "");
      const asMatch = noType.match(/^([A-Za-z_$][\w$]*)\s+as\s+([A-Za-z_$][\w$]*)$/);
      if (asMatch) {
        symbols.add(asMatch[2]);
        continue;
      }
      // Plain "name" or "type name" without alias.
      const nameMatch = noType.match(/^([A-Za-z_$][\w$]*)$/);
      if (nameMatch) {
        symbols.add(nameMatch[1]);
      }
    }
  }

  // 2. CJS-style `export = name`. The exported symbol is exposed under its
  //    declared name and represents the default export — record it as
  //    "default" so it is comparable across the two formats.
  for (const match of stripped.matchAll(/export\s*=\s*([A-Za-z_$][\w$]*)\s*;?/g)) {
    symbols.add("default");
    // The named symbol on the left is also still declared; if it is also
    // re-exported in a list above, it appears there too. Don't add it
    // separately — `export =` is the default-export form.
    void match;
  }

  // 3. ES `export default <name>` form (rare in tsup output but possible).
  if (/\bexport\s+default\s+/.test(stripped)) {
    symbols.add("default");
  }

  // 4. Inline `export declare function|class|const|var|let|interface|type|enum
  //    Name`. tsup occasionally emits these alongside the consolidated export
  //    list (for example, when an internal helper is re-exported). Catch them
  //    so the script does not undercount.
  const inlineRe =
    /export\s+(?:declare\s+)?(?:function|class|const|var|let|interface|type|enum)\s+([A-Za-z_$][\w$]*)/g;
  for (const match of stripped.matchAll(inlineRe)) {
    symbols.add(match[1]);
  }

  return symbols;
}

/**
 * @param {Set<string>} a
 * @param {Set<string>} b
 * @returns {{onlyA: string[], onlyB: string[]}}
 */
function diffSymbols(a, b) {
  const onlyA = [...a].filter((s) => !b.has(s)).sort();
  const onlyB = [...b].filter((s) => !a.has(s)).sort();
  return { onlyA, onlyB };
}

async function main() {
  let dtsSource;
  let dctsSource;
  try {
    dtsSource = await readFile(dtsPath, "utf8");
  } catch (err) {
    console.error(`[check-dts-parity] Failed to read ${dtsPath}: ${err.message}`);
    console.error("[check-dts-parity] Did you run `npm run build` first?");
    process.exit(1);
  }
  try {
    dctsSource = await readFile(dctsPath, "utf8");
  } catch (err) {
    console.error(`[check-dts-parity] Failed to read ${dctsPath}: ${err.message}`);
    console.error("[check-dts-parity] Did you run `npm run build` first?");
    process.exit(1);
  }

  const dtsSymbols = extractExportedSymbols(dtsSource);
  const dctsSymbols = extractExportedSymbols(dctsSource);

  if (dtsSymbols.size === 0 || dctsSymbols.size === 0) {
    console.error(
      "[check-dts-parity] One of the declaration files exposed zero exported symbols — extraction likely failed. Inspect the regex against the actual emitted .d.ts/.d.cts.",
    );
    console.error(`[check-dts-parity] dist/index.d.ts  -> ${dtsSymbols.size} symbol(s) detected`);
    console.error(`[check-dts-parity] dist/index.d.cts -> ${dctsSymbols.size} symbol(s) detected`);
    process.exit(1);
  }

  const { onlyA: onlyInDts, onlyB: onlyInDcts } = diffSymbols(dtsSymbols, dctsSymbols);

  if (onlyInDts.length === 0 && onlyInDcts.length === 0) {
    console.log(
      `[check-dts-parity] OK — both dist/index.d.ts and dist/index.d.cts expose ${dtsSymbols.size} matching symbol(s).`,
    );
    return;
  }

  console.error("[check-dts-parity] FAIL — exported symbol sets diverge:");
  if (onlyInDts.length > 0) {
    console.error(`  Only in dist/index.d.ts  (${onlyInDts.length}): ${onlyInDts.join(", ")}`);
  }
  if (onlyInDcts.length > 0) {
    console.error(`  Only in dist/index.d.cts (${onlyInDcts.length}): ${onlyInDcts.join(", ")}`);
  }
  console.error(
    "[check-dts-parity] Inspect the tsup output for the missing symbol and adjust the source/exports in src/index.ts so both formats expose the same public surface.",
  );
  process.exit(1);
}

main().catch((err) => {
  console.error("[check-dts-parity] Unexpected error:", err);
  process.exit(1);
});
