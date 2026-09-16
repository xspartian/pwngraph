// Copies the built SPA (frontend/dist/) into pwngraph/api/static/, where
// `pwngraph serve` (pwngraph/cli/main.py) and the packaged wheel
// ([tool.setuptools.package-data] in pyproject.toml) both expect it.
// Run via `npm run build:pwngraph`.

import { cpSync, existsSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const src = join(here, "..", "dist");
const dest = join(here, "..", "..", "pwngraph", "api", "static");

if (!existsSync(src)) {
  console.error(`No build output at ${src} — run "npm run build" first.`);
  process.exit(1);
}

rmSync(dest, { recursive: true, force: true });
cpSync(src, dest, { recursive: true });
console.log(`Copied ${src} -> ${dest}`);
