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
  async onSuccess() {
    // Copy custom CommonJS type definitions
    const fs = await import("fs");
    const path = await import("path");
    const src = path.join(process.cwd(), "src/index.d.cts");
    const dest = path.join(process.cwd(), "dist/index.d.cts");
    await fs.promises.copyFile(src, dest);
    console.log("✓ Copied custom CommonJS type definitions");
  },
});
