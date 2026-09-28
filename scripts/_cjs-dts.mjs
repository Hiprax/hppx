// @ts-check
/**
 * _cjs-dts.mjs
 *
 * Pure transform from the ESM declaration file tsup emits (`dist/index.d.ts`)
 * to the CommonJS declaration file (`dist/index.d.cts`).
 *
 * At runtime `require("hppx")` returns the middleware factory itself, with
 * every named export (and `default`) attached as a property: see the footer in
 * `tsup.config.ts`. The legal declaration of that shape is `export =` plus a
 * namespace merged with the function. `export =` next to other exports is an
 * error (TS2309), and TypeScript 7 no longer honours the `// @ts-ignore` that
 * tsup's `cjsInterop` option used to put in front of it. So the body is kept
 * as is and the final `export { ... }` list moves into
 * `declare namespace <name> { ... }`.
 *
 * Side-effect free: `scripts/write-cjs-dts.mjs` does the file IO, and tests
 * import this module directly.
 */

import { escapeRegex } from "./_lib.mjs";

const IDENTIFIER = "[A-Za-z_$][\\w$]*";

/**
 * Returns the contents of `dist/index.d.cts` for the given `dist/index.d.ts`.
 * Throws when the input does not have the expected shape, so a change in the
 * bundler's output fails the build instead of shipping wrong declarations.
 *
 * @param {string} dtsSource
 * @returns {string}
 */
export function toCjsDeclaration(dtsSource) {
  const lines = dtsSource.replace(/\r\n/g, "\n").trimEnd().split("\n");
  const last = lines.pop() ?? "";
  const list = /^export \{ ([^{}]+) \};$/.exec(last);
  if (!list) {
    throw new Error(
      "toCjsDeclaration: the last statement of index.d.ts must be a one-line `export { ... };` list",
    );
  }

  const members = (list[1] ?? "")
    .split(",")
    .map((entry) => entry.trim().replace(/^type\s+/, ""))
    .filter((entry) => entry.length > 0);
  const memberRe = new RegExp(`^${IDENTIFIER}(?: as ${IDENTIFIER})?$`);
  for (const member of members) {
    if (!memberRe.test(member)) {
      throw new Error(`toCjsDeclaration: unexpected export list entry "${member}"`);
    }
  }

  const defaultRe = new RegExp(`^(${IDENTIFIER}) as default$`);
  const defaults = members.filter((member) => defaultRe.test(member));
  if (defaults.length !== 1) {
    throw new Error(
      `toCjsDeclaration: expected exactly one "<name> as default" entry, found ${defaults.length}`,
    );
  }
  const name = (defaultRe.exec(defaults[0] ?? "") ?? [])[1] ?? "";

  const body = lines.join("\n").trimEnd();
  const stray = body.split("\n").find((line) => /^export\b/.test(line));
  if (stray !== undefined) {
    throw new Error(
      `toCjsDeclaration: unexpected top-level export before the final list: ${stray}`,
    );
  }
  if (!new RegExp(`^declare function ${escapeRegex(name)}[<(]`, "m").test(body)) {
    throw new Error(
      `toCjsDeclaration: the default export "${name}" must be a declared function, so that a namespace can merge with it`,
    );
  }

  return [
    body,
    "",
    `// CommonJS: require("hppx") returns ${name} with every named export attached.`,
    `declare namespace ${name} {`,
    `    export { ${members.join(", ")} };`,
    "}",
    `export = ${name};`,
    "",
  ].join("\n");
}
