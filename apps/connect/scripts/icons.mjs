import { copyFileSync, cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const app = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const scratch = resolve(app, "../../temp/branding");
const source = readFileSync(resolve(app, "public/brand/logo.svg"), "utf8");
// Keep the official paths and viewBox intact; center the complete mark on white.
const artwork = source.slice(source.indexOf("<svg"))
  .replace(/\bwidth="[^"]*"/, 'x="80" width="864"')
  .replace(/\bheight="[^"]*"/, 'y="80" height="864"');
if (!artwork.startsWith("<svg")) throw new Error("Official logo SVG is missing");
mkdirSync(scratch, { recursive: true });
const input = resolve(scratch, "app-icon.svg");
writeFileSync(input, `<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024"><rect width="1024" height="1024" fill="white"/>${artwork}</svg>\n`);

const result = spawnSync(process.execPath, [
  resolve(app, "node_modules/@tauri-apps/cli/tauri.js"), "icon", input,
  "--output", resolve(app, "src-tauri/icons"), "--ios-color", "#ffffff",
], { cwd: app, stdio: "inherit" });
if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status ?? 1);
copyFileSync(resolve(app, "src-tauri/icons/32x32.png"), resolve(app, "public/brand/favicon.png"));
const androidResources = resolve(app, "src-tauri/gen/android/app/src/main/res");
if (existsSync(androidResources))
  cpSync(resolve(app, "src-tauri/icons/android"), androidResources, { recursive: true });
