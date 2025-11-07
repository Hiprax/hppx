import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  clean: true,
  dts: true,
  sourcemap: true,
  format: ["esm", "cjs"],
  target: "es2020",
  minify: false,
});
