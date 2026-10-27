import { test } from "node:test";
import assert from "node:assert/strict";
import {
  primaryScreen,
  filterFiles,
  formatBytes,
  folderCrumbs,
  friendlyProblem,
  type HomeStatus,
} from "../src/home-state.ts";
const blank: HomeStatus = {
  owner: false,
  configured: false,
  network: null,
  peer: null,
  devices: [],
  selected_device: null,
  ready: false,
  sharing: null,
  joining: null,
  request: null,
  problem: null,
  legacy: false,
};
test("approval remains visible while a certificate is being installed", () => {
  assert.equal(primaryScreen(blank), "welcome");
  assert.equal(primaryScreen({ ...blank, configured: true }), "workspace");
  assert.equal(
    primaryScreen({
      ...blank,
      configured: true,
      joining: "Waiting for approval",
    }),
    "joining",
  );
});
test("ordinary connection errors explain the next action without exposing protocol details", () => {
  assert.match(friendlyProblem("closed by peer: session ended (code 0)"), /Keep Connect open/);
  assert.match(friendlyProblem("The file changed. Refresh the file list"), /Refresh/);
  assert.match(friendlyProblem("current folder permission. Share the folder again to allow larger files"), /Share this folder again/);
  assert.equal(friendlyProblem("TLS_EXPORTER protocol internals"), "Couldn’t complete this. Please try again.");
});
test("file search filters actual returned entries without changing their version", () => {
  const file = { name: "Family Notes.txt", kind: "file" as const, bytes: 123, version: "abc" };
  assert.deepEqual(filterFiles([file], " FAMILY "), [file]);
  assert.equal(filterFiles([file], "../secret").length, 0);
  assert.equal(formatBytes(123), "123 B");
  assert.equal(formatBytes(65536), "64.0 KB");
  assert.equal(formatBytes(1048576), "1.0 MB");
  assert.equal(formatBytes(1073741824), "1.0 GB");
});

test("breadcrumbs preserve Unicode names and return explicit parent paths", () => {
  const directory = ["Photos", "Été 2026"];
  assert.deepEqual(folderCrumbs(directory), [
    {name:"Shared folder",directory:[]},
    {name:"Photos",directory:["Photos"]},
    {name:"Été 2026",directory:["Photos","Été 2026"]},
  ]);
  assert.deepEqual(directory,["Photos","Été 2026"]);
});
