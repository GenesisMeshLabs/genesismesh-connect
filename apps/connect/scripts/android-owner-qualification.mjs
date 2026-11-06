import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

export const packageId = "org.genesismesh.connect.ownerqualification";
const start = "// BEGIN CONNECT OWNER QUALIFICATION";
const end = "// END CONNECT OWNER QUALIFICATION";

export function patchGradle(text, fragment, version) {
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error("Review the Chaquopy plugin pin");
  for (const field of ["namespace", "applicationId"])
    if (!new RegExp(`\\b${field} = "${packageId.replaceAll(".", "\\.")}"`).test(text))
      throw new Error("Refusing to patch a non-owner qualification application");
  if (!/\bminSdk = \d+/.test(text)) throw new Error("Review the generated minSdk");
  text = text.replace(/\bminSdk = \d+/, "minSdk = 35");
  if (text.includes('id("com.chaquo.python")')) {
    if (!text.includes(`id("com.chaquo.python") version "${version}"`)) throw new Error("Chaquopy plugin pin drift");
  } else text = text.replace("plugins {", `plugins {\n    id("com.chaquo.python") version "${version}"`);
  if (!text.includes(`id("com.chaquo.python") version "${version}"`)) throw new Error("Missing plugins block");
  if (text.includes(start)) {
    const first = text.indexOf(start), last = text.indexOf(end);
    if (last < first || text.indexOf(start, first + start.length) !== -1) throw new Error("Invalid qualification block");
    text = text.slice(0, first).trimEnd() + text.slice(last + end.length);
  }
  return `${text.trimEnd()}\n\n${start}\n${fragment.trim()}\n${end}\n`;
}

function main() {
  const app = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const repository = resolve(app, "../..");
  const mode = process.argv[2] ?? "init";
  if (!["init", "patch-existing", "bridge-only"].includes(mode) || process.argv.length > 3)
    throw new Error("Use init, patch-existing or bridge-only; this never builds, installs or operates a device");
  if (mode === "bridge-only") {
    const project = resolve(repository, "spikes/android-owner-bridge");
    const base = readFileSync(resolve(project, "build.gradle.kts"), "utf8");
    const fragment = readFileSync(resolve(app, "native/android/owner-qualification.gradle.kts"), "utf8");
    writeFileSync(resolve(project, "generated.gradle.kts"), `${base}\n${fragment}`);
    return;
  }
  const config = resolve(app, "temp/owner-qualification.conf.json");
  mkdirSync(dirname(config), { recursive: true });
  writeFileSync(config, JSON.stringify({ identifier: packageId, productName: "GM Owner Qualification" }) + "\n");
  if (mode === "init") {
    const result = spawnSync(process.execPath, [resolve(app, "scripts/android-init.mjs"), "--ci", "--config", config], { cwd: app, stdio: "inherit" });
    if (result.error) throw result.error;
    if (result.status !== 0) throw new Error("Android qualification initialization failed");
  }
  const pin = readFileSync(resolve(repository, "spikes/android-authority/build.gradle.kts"), "utf8");
  const matches = [...pin.matchAll(/id\("com\.chaquo\.python"\) version "([\d.]+)"/g)];
  if (matches.length !== 1) throw new Error("Review the qualified Chaquopy pin");
  const project = resolve(app, "src-tauri/gen/android/app");
  const gradle = resolve(project, "build.gradle.kts");
  writeFileSync(gradle, patchGradle(readFileSync(gradle, "utf8"),
    readFileSync(resolve(app, "native/android/owner-qualification.gradle.kts"), "utf8"), matches[0][1]));
  const manifest = resolve(project, "src/main/AndroidManifest.xml");
  let xml = readFileSync(manifest, "utf8");
  if (!xml.includes('android.permission.USE_BIOMETRIC'))
    xml = xml.replace("<application", '<uses-permission android:name="android.permission.USE_BIOMETRIC" />\n    <application');
  writeFileSync(manifest, xml);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
