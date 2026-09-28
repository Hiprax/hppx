import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  clean: true,
  dts: {
    resolve: true,
  },
  sourcemap: true,
  format: ["esm", "cjs"],
  target: "es2020",
  minify: false,
  outExtension({ format }) {
    return {
      js: format === "esm" ? ".mjs" : ".cjs",
    };
  },
  // Off on purpose. For this entry (named exports beside the default) its JS
  // step is a no-op, and its declaration step writes `// @ts-ignore` +
  // `export = hppx` next to named exports, which TypeScript 7 rejects. The
  // CommonJS shape comes from the footer below, and `npm run build` rewrites
  // `dist/index.d.cts` with `scripts/write-cjs-dts.mjs`.
  cjsInterop: false,
  splitting: false,
  esbuildOptions(options, context) {
    // Add a footer to CommonJS output to ensure require("hppx") works without .default
    // while preserving named exports
    if (context.format === "cjs") {
      options.footer = {
        js: "if (module.exports.default) { module.exports = Object.assign(module.exports.default, module.exports); }",
      };
    }
  },
  // Note: tsup generates `dist/index.d.ts` from `src/index.ts`; its own
  // `dist/index.d.cts` is ESM-shaped and is replaced by
  // `scripts/write-cjs-dts.mjs` (part of `npm run build`, not of `npm run dev`,
  // whose `.d.cts` therefore stays ESM-shaped). `npm run check-dts` verifies
  // symbol parity, the CommonJS declaration shape and real consumer imports.
});
