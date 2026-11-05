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
