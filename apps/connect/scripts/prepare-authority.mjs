import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

// Package only a native desktop sidecar, never the build host's executable
// into a mobile application or a different desktop target.
const target = process.env.TAURI_ENV_PLATFORM;
const host = { win32: "windows", darwin: "darwin", linux: "linux" }[process.platform];
if (!host || (target && !["windows", "darwin", "linux"].includes(target))) process.exit(0);
if (target && target !== host)
  throw new Error("Package the authority on the target desktop OS");
if (!["x64", "arm64"].includes(process.arch))
  throw new Error(
    "Build the authority for the target architecture before packaging this platform.",
  );
const app = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const root = resolve(app, "../..");
const python =
  process.env.CONNECT_NA_PYTHON ??
  (process.platform === "win32" ? resolve(root, "../genesismesh/.venv/Scripts/python.exe") : "python3");
if (process.platform === "win32" && !existsSync(python))
  throw new Error(
    "The build needs Genesis Mesh 1.8.1. Set CONNECT_NA_PYTHON to its build environment. Installed apps use the bundled runtime.",
  );
const env = { ...process.env, PYTHONDONTWRITEBYTECODE: "1" };
function run(args) {
  const result = spawnSync(python, args, { cwd: app, env, stdio: "inherit" });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}
run([resolve(app, "authority/package.py")]);
