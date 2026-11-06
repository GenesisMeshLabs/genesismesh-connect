import test from "node:test";
import assert from "node:assert/strict";
import { patchGradle, packageId } from "../scripts/android-owner-qualification.mjs";

const source = `plugins {\n id("rust")\n}\nandroid {\n namespace = "${packageId}"\n defaultConfig {\n applicationId = "${packageId}"\n minSdk = 24\n }\n}\n`;
test("owner packaging is opt-in, isolated and repeatable", () => {
  const patched = patchGradle(source, "// fixture owner runtime", "17.2.0");
  assert.match(patched, /minSdk = 35/);
  assert.equal(patchGradle(patched, "// fixture owner runtime", "17.2.0"), patched);
  assert.equal((patched.match(/com\.chaquo\.python/g) || []).length, 1);
  assert.match(patchGradle(patched, "// updated runtime", "17.2.0"), /updated runtime/);
});
test("ordinary app identities and changed plugin pins are refused", () => {
  assert.throws(() => patchGradle(source.replaceAll(packageId, "org.genesismesh.connect"), "", "17.2.0"));
  assert.throws(() => patchGradle(source.replace('id("rust")', 'id("com.chaquo.python") version "0.0.0"'), "", "17.2.0"));
  assert.throws(() => patchGradle(source, "", "unreviewed"));
  assert.throws(() => patchGradle(source.replace("plugins {", "missing {"), "", "17.2.0"));
});
