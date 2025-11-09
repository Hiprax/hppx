import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  clean: true,
  dts: true,
  sourcemap: true,
  format: ["esm", "cjs"],
  target: "es2020",
  minify: false,
  outExtension({ format }) {
    return {
      js: format === "esm" ? ".mjs" : ".cjs",
    };
  },
  // Ensure proper CommonJS default export
  cjsInterop: true,
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
});
