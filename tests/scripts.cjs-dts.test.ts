import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

// scripts/_cjs-dts.mjs is an ES module; Jest (ts-jest, CommonJS) runs it in a
// child process, as tests/scripts.run.test.ts does for scripts/_lib.mjs. The
// module is side-effect free, so nothing is written to dist/.
const root = resolve(__dirname, "..");
const moduleUrl = pathToFileURL(resolve(root, "scripts", "_cjs-dts.mjs")).href;

const BODY = [
  'declare module "express-serve-static-core" {',
  "    interface Request {",
  "        queryPolluted?: Record<string, unknown>;",
  "    }",
  "}",
  'type Mode = "a" | "b";',
  "interface Options {",
  "    mode?: Mode;",
  "}",
  "declare const LIST: readonly string[];",
  "declare function helper(): void;",
  "declare function factory(options?: Options): () => void;",
].join("\n");
const LIST = "export { LIST, type Mode, type Options, factory as default, helper };";
const INPUT = `${BODY}\n\n${LIST}\n`;

const EXPECTED = [
  BODY,
  "",
  '// CommonJS: require("hppx") returns factory with every named export attached.',
  "declare namespace factory {",
  "    export { LIST, Mode, Options, factory as default, helper };",
  "}",
  "export = factory;",
  "",
].join("\n");

/** Runs toCjsDeclaration on each input and returns the output or the error message. */
function transform(
  inputs: Record<string, string>,
): Record<string, { out?: string; error?: string }> {
  const script = [
    `import { toCjsDeclaration } from ${JSON.stringify(moduleUrl)};`,
    `const inputs = ${JSON.stringify(inputs)};`,
    "const results = {};",
    "for (const [name, input] of Object.entries(inputs)) {",
    "  try { results[name] = { out: toCjsDeclaration(input) }; }",
    "  catch (err) { results[name] = { error: err.message }; }",
    "}",
    "process.stdout.write(JSON.stringify(results));",
  ].join("\n");
  const stdout = execFileSync(process.execPath, ["--input-type=module", "-e", script], {
    cwd: root,
    encoding: "utf8",
  });
  return JSON.parse(stdout) as Record<string, { out?: string; error?: string }>;
}

describe("scripts/_cjs-dts.mjs: CommonJS declarations derived from the ESM ones", () => {
  let results: Record<string, { out?: string; error?: string }> = {};
  beforeAll(() => {
    results = transform({
      golden: INPUT,
      crlf: INPUT.replace(/\n/g, "\r\n"),
      noDefault: `${BODY}\n\nexport { LIST, helper };\n`,
      twoDefaults: `${BODY}\n\nexport { factory as default, helper as default };\n`,
      strayExport: `${BODY}\nexport declare const EXTRA: 1;\n\n${LIST}\n`,
      existingExportEquals: `${BODY}\nexport = factory;\n\n${LIST}\n`,
      defaultNotFunction: `${BODY.replace(
        "declare function factory(options?: Options): () => void;",
        "declare const factory: () => void;",
      )}\n\n${LIST}\n`,
      listNotLast: `${BODY}\n\n${LIST}\ndeclare const tail: 1;\n`,
      oddEntry: `${BODY}\n\nexport { * as ns, factory as default };\n`,
    });
  });

  it("moves the export list into a namespace merged with the default function, behind export =", () => {
    expect(results.golden).toEqual({ out: EXPECTED });
  });

  it("gives the same output for CRLF input", () => {
    expect(results.crlf).toEqual({ out: EXPECTED });
  });

  it("never silences the compiler and keeps exactly one export assignment", () => {
    const out = results.golden?.out ?? "";
    expect(out).not.toMatch(/@ts-(?:ignore|nocheck|expect-error)/);
    expect(out.match(/^export = /gm)).toHaveLength(1);
    expect(out).not.toMatch(/^export \{/m);
  });

  it.each([
    ["noDefault", 'expected exactly one "<name> as default" entry, found 0'],
    ["twoDefaults", 'expected exactly one "<name> as default" entry, found 2'],
    ["strayExport", "unexpected top-level export before the final list: export declare const"],
    [
      "existingExportEquals",
      "unexpected top-level export before the final list: export = factory;",
    ],
    ["defaultNotFunction", 'the default export "factory" must be a declared function'],
    ["listNotLast", "the last statement of index.d.ts must be a one-line `export { ... };` list"],
    ["oddEntry", 'unexpected export list entry "* as ns"'],
  ])("rejects input with %s instead of guessing", (name, message) => {
    const result = results[name];
    expect(result?.out).toBeUndefined();
    expect(result?.error).toContain(message);
  });
});
