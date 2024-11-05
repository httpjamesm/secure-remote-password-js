import dts from "bun-plugin-dts";
import { build } from "esbuild";

// Build ESM version
await build({
  entryPoints: ["./src/index.ts"],
  outfile: "./dist/index.js",
  format: "esm",
  platform: "node",
  bundle: true,
  external: ["node:crypto"], // Mark node built-ins as external
});

// Build CJS version
await build({
  entryPoints: ["./src/index.ts"],
  outfile: "./dist/index.cjs",
  format: "cjs",
  platform: "node",
  bundle: true,
  external: ["node:crypto"],
});

// Build type declarations
await Bun.build({
  entrypoints: ["./src/index.ts"],
  outdir: "./dist",
  plugins: [dts()],
});
