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
});
