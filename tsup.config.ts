import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    "exports/index": "src/exports/index.ts",
    "exports/types": "src/exports/types.ts",
    "exports/engine": "src/exports/engine.ts",
    "exports/traffic": "src/exports/traffic.ts",
    "exports/store": "src/exports/store.ts",
    "exports/assets": "src/exports/assets.ts",
    "exports/auth": "src/exports/auth.ts",
    "exports/validate": "src/exports/validate.ts",
    "exports/export-lib": "src/exports/export-lib.ts",
    "exports/siren": "src/exports/siren.ts",
    "exports/rate-limit": "src/exports/rate-limit.ts",
    "exports/csrf": "src/exports/csrf.ts",
    "exports/errors": "src/exports/errors.ts",
    "exports/db": "src/exports/db.ts",
    "exports/inspector": "src/exports/inspector.ts",
    "exports/ui": "src/exports/ui.tsx",
  },
  format: ["esm"],
  dts: true,
  sourcemap: true,
  clean: true,
  external: [
    "next",
    "react",
    "react-dom",
    "jose",
    "bcryptjs",
    "better-sqlite3",
    "zod",
  ],
  esbuildOptions(options) {
    options.alias = {
      "@": "./src",
    };
  },
  tsconfig: "tsconfig.lib.json",
});
