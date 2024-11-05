import type { BuildConfig } from "bun";
import dts from "bun-plugin-dts";
import { build } from "esbuild";

const defaultBuildConfig: BuildConfig = {
  entrypoints: ["./src/index.ts"],
  outdir: "./dist",
};

// Build ESM version
await Bun.build({
  ...defaultBuildConfig,
  format: "esm",
  naming: "[dir]/[name].js",
});

// Build CJS version using esbuild
await build({
  entryPoints: ["./src/index.ts"],
  outfile: "./dist/index.cjs",
  format: "cjs",
  platform: "node",
  bundle: true,
});

// Build type declarations
await Bun.build({
  ...defaultBuildConfig,
  plugins: [dts()],
});
