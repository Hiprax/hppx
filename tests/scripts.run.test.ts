import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = resolve(__dirname, "..");
const libUrl = pathToFileURL(resolve(root, "scripts", "_lib.mjs")).href;

describe("scripts/_lib.mjs — run() argument handling", () => {
  it("preserves a space-containing argument as a single argv entry", () => {
    // The inner node process prints its own argv as JSON so we can verify
    // that "release v9.9.9" (with an embedded space) was NOT re-split by the shell.
    const innerCode = `process.stdout.write(JSON.stringify(process.argv.slice(1)))`;

    // Build an ESM script that imports run() and invokes it with a spaced arg.
    const outerScript = [
      `import { run } from ${JSON.stringify(libUrl)};`,
      `const r = await run("node", ["-e", ${JSON.stringify(innerCode)}, "release v9.9.9"], { silent: true });`,
      `process.stdout.write(r.stdout);`,
    ].join("\n");

    const out = execFileSync(process.execPath, ["--input-type=module", "-e", outerScript], {
      cwd: root,
      encoding: "utf8",
    });

    const argv = JSON.parse(out) as string[];
    // "release v9.9.9" must arrive as one element, not split into "release" + "v9.9.9".
    expect(argv).toContain("release v9.9.9");
    expect(argv).not.toContain("release");
    expect(argv).not.toContain("v9.9.9");
  });
});
