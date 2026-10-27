import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

if (process.platform !== "darwin")
  throw new Error("iOS setup requires macOS and Xcode");
const app = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const project = resolve(app, "src-tauri/gen/apple");
const pbx = resolve(project, "genesismesh-connect.xcodeproj/project.pbxproj");
const env = { ...process.env };

// Preserve a team already selected in Xcode when regenerating local files.
if (!env.APPLE_DEVELOPMENT_TEAM && existsSync(pbx)) {
  const teams = new Set(
    [
      ...readFileSync(pbx, "utf8").matchAll(
        /DEVELOPMENT_TEAM = "?([A-Z0-9]+)"?;/g,
      ),
    ].map((match) => match[1]),
  );
  if (teams.size > 1)
    throw new Error(
      "Multiple signing teams found; set APPLE_DEVELOPMENT_TEAM explicitly",
    );
  if (teams.size === 1) env.APPLE_DEVELOPMENT_TEAM = [...teams][0];
}

function run(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, env, stdio: "inherit" });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

const args = process.argv.slice(2);
const patchExisting = args.includes("--patch-existing");
if (patchExisting && args.length !== 1)
  throw new Error("Use --patch-existing without init arguments");
if (!patchExisting)
  run(
    process.execPath,
    [
      resolve(app, "node_modules/@tauri-apps/cli/tauri.js"),
      "ios",
      "init",
      ...args,
    ],
    app,
  );
const specPath = resolve(project, "project.yml");
let spec = readFileSync(specPath, "utf8");
// XcodeGen's project defaults can differ from Xcode's. Keep this protection
// explicit, including after regenerating a project edited by Xcode.
const sandboxSetting = /^        ENABLE_USER_SCRIPT_SANDBOXING:.*$/gm;
if ([...spec.matchAll(sandboxSetting)].length > 1)
  throw new Error("Multiple script sandbox settings require review");
if (sandboxSetting.test(spec))
  spec = spec.replace(
    sandboxSetting,
    "        ENABLE_USER_SCRIPT_SANDBOXING: true",
  );
else {
  const anchor = "        ENABLE_BITCODE: false";
  if (spec.split(anchor).length !== 2)
    throw new Error("Unexpected iOS target settings");
  spec = spec.replace(
    anchor,
    `${anchor}\n        ENABLE_USER_SCRIPT_SANDBOXING: true`,
  );
}
// Xcode edits the pbxproj directly. Carry its selected team into XcodeGen's
// source spec too, so patching an existing project preserves that selection.
if (env.APPLE_DEVELOPMENT_TEAM) {
  if (!/^[A-Z0-9]+$/.test(env.APPLE_DEVELOPMENT_TEAM))
    throw new Error("Invalid development team identifier");
  const teamLine = `      DEVELOPMENT_TEAM: "${env.APPLE_DEVELOPMENT_TEAM}"`;
  const existingTeam = /^      DEVELOPMENT_TEAM:.*$/gm;
  const matches = [...spec.matchAll(existingTeam)];
  if (matches.length > 1)
    throw new Error("Multiple generated team settings require review");
  if (matches.length === 1) spec = spec.replace(existingTeam, teamLine);
  else {
    const anchor = "      PRODUCT_BUNDLE_IDENTIFIER:";
    if (spec.split(anchor).length !== 2)
      throw new Error("Unexpected Xcode signing settings");
    spec = spec.replace(anchor, `${teamLine}\n${anchor}`);
  }
}
// Keep the Rust build script sandboxed while allowing its generated CLI input.
// The CLI creates this file before invoking xcodebuild.
if (!spec.includes("        inputFiles:")) {
  const anchor = "        basedOnDependencyAnalysis: false";
  if (spec.split(anchor).length !== 2)
    throw new Error("Unexpected Rust build phase inputs");
  spec = spec.replace(anchor, `${anchor}\n        inputFiles:`);
}
if (spec.split("        inputFiles:").length !== 2)
  throw new Error("Multiple build phase inputs require review");
const rustInputs = [
  "$(SRCROOT)/.tauri/cli-options-server.json",
  "$(SRCROOT)/genesismesh-connect.xcodeproj/project.pbxproj",
];
for (const input of rustInputs) {
  if (
    !spec
      .split("        inputFiles:")[1]
      .split("        outputFiles:")[0]
      .includes(`          - ${input}`)
  )
    spec = spec.replace(
      "        inputFiles:",
      `        inputFiles:\n          - ${input}`,
    );
}
// Regeneration after a build must link static archives, not copy them as resources.
if (
  spec.includes("      - path: Externals\n") &&
  !spec.includes('excludes: ["**/*.a"]')
) {
  spec = spec.replace(
    "      - path: Externals\n",
    '      - path: Externals\n        excludes: ["**/*.a"]\n',
  );
}
// Tauri's frameworks option cannot express SDK .tbd libraries. Rust static
// libraries require libresolv to be linked by the final Xcode application.
if (!spec.includes("      - sdk: libresolv.tbd")) {
  const anchor = "      - sdk: WebKit.framework";
  if (spec.split(anchor).length !== 2)
    throw new Error(
      "Unexpected Tauri Xcode template; review SDK library placement",
    );
  spec = spec.replace(anchor, "      - sdk: libresolv.tbd\n" + anchor);
}
writeFileSync(specPath, spec);
// Tauri merges Info.ios.plist after its first XcodeGen pass. Preserve that
// merged file when adding the SDK library in a second generation pass.
const infoPath = resolve(project, "genesismesh-connect_iOS/Info.plist");
const mergedInfo = readFileSync(infoPath);
run("xcodegen", ["generate", "--spec", specPath], project);
writeFileSync(infoPath, mergedInfo);
// Declare the iOS join scheme in the owned manifest before Xcode runs. The
// plugin still delivers Opened events, without rewriting signing inputs from
// inside the sandboxed Rust phase (which would create an Xcode build cycle).
run(
  "python3",
  [
    "-c",
    "import pathlib,plistlib,sys; target=pathlib.Path(sys.argv[1]); info=plistlib.loads(target.read_bytes()); info.update(plistlib.loads(pathlib.Path(sys.argv[2]).read_bytes())); target.write_bytes(plistlib.dumps(info))",
    infoPath,
    resolve(app, "src-tauri/Info.ios.plist"),
  ],
  app,
);
// Tauri init creates a separate asset catalog. Regenerate the official brand
// into that catalog after project generation, including --patch-existing.
run(process.execPath, [resolve(app, "scripts/icons.mjs")], app);
