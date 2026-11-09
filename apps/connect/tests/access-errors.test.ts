import { test } from "node:test";
import assert from "node:assert/strict";
import { friendlyProblem } from "../src/home-state.ts";
test("access recovery errors give a precise next action instead of generic retry",()=>{
  assert.match(friendlyProblem("This review expired; review current settings"),/Change choices/);
  assert.match(friendlyProblem("Access changed since your review"),/Reload/);
  assert.match(friendlyProblem("An earlier access change has an uncertain result"),/Check status/);
  assert.match(friendlyProblem("Update the network computer: its Genesis Mesh version is incompatible"),/Update Connect/);
  assert.match(friendlyProblem("Workflow history needs attention"),/preserved/);
});

test("a device that refuses a network restored from an older file says why",()=>{
  assert.match(friendlyProblem("Trust refresh failed: CRL rollback"),/restored from a recovery file older than what this device has seen/);
  assert.match(friendlyProblem("Key history rollback or equivocation"),/leave and join again/);
});
