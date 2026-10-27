import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const app = resolve(dirname(fileURLToPath(import.meta.url)), "..");
function run(args) {
  const result = spawnSync(process.execPath, args, { cwd: app, stdio: "inherit" });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}
const args = process.argv.slice(2);
if (args.includes("--patch-existing")) {
  if (args.length !== 1) throw new Error("Use --patch-existing without init arguments");
} else {
  run([resolve(app, "node_modules/@tauri-apps/cli/tauri.js"), "android", "init", ...args]);
}
const project = resolve(app, "src-tauri/gen/android");
const gradlePath = resolve(project, "app/build.gradle.kts");
if (!existsSync(gradlePath)) throw new Error("Initialize the Android project first");
let gradle = readFileSync(gradlePath, "utf8");
for (const field of ["compileSdk", "targetSdk"]) {
  const pattern = new RegExp(`\\b${field} = \\d+`, "g");
  if ([...gradle.matchAll(pattern)].length !== 1)
    throw new Error(`Review the generated Android ${field} setting`);
  gradle = gradle.replace(pattern, `${field} = 36`);
}
writeFileSync(gradlePath, gradle);
const manifestPath = resolve(project, "app/src/main/AndroidManifest.xml");
let manifest = readFileSync(manifestPath, "utf8");
// Restoring encrypted preferences onto another phone cannot restore its
// device-bound Keystore key. Never offer a misleading recoverable backup.
if (/android:allowBackup=/.test(manifest))
  manifest = manifest.replace(/android:allowBackup="[^"]*"/, 'android:allowBackup="false"');
else manifest = manifest.replace("<application", '<application android:allowBackup="false"');
// Web services reach only the native loopback tunnel over HTTP. Keep ordinary
// network traffic under Android's TLS default, including release builds.
if (/android:networkSecurityConfig=/.test(manifest))
  manifest = manifest.replace(/android:networkSecurityConfig="[^"]*"/, 'android:networkSecurityConfig="@xml/connect_network_security"');
else manifest = manifest.replace("<application", '<application android:networkSecurityConfig="@xml/connect_network_security"');
writeFileSync(manifestPath, manifest);
writeFileSync(resolve(project, "app/src/main/res/xml/connect_network_security.xml"), `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="false" />
  <domain-config cleartextTrafficPermitted="true"><domain>127.0.0.1</domain><domain>localhost</domain></domain-config>
</network-security-config>
`);
// Preserve Tauri's existing debug-only HTTP development-server support.
const debugXml = resolve(project, "app/src/debug/res/xml");
mkdirSync(debugXml, { recursive: true });
writeFileSync(resolve(debugXml, "connect_network_security.xml"), `<?xml version="1.0" encoding="utf-8"?>
<network-security-config><base-config cleartextTrafficPermitted="true" /></network-security-config>
`);
// Only verified downloads may be offered to another app through FileProvider.
writeFileSync(resolve(project, "app/src/main/res/xml/file_paths.xml"), `<?xml version="1.0" encoding="utf-8"?>
<paths xmlns:android="http://schemas.android.com/apk/res/android">
  <cache-path name="connect_downloads" path="connect-downloads/" />
</paths>
`);
run([resolve(app, "scripts/icons.mjs")]);
