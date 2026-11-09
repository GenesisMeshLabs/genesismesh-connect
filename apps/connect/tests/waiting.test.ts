import {test} from "node:test";
import assert from "node:assert/strict";
import {elapsed,waitTitle,waitDetail,stoppedWaiting,finishingTitle,finishingDetail,STOPPED,WAIT_LIMIT_MS,EXPLAIN_AFTER_MS} from "../src/waiting.ts";

test("a wait shows minutes and seconds since it began",()=>{
  assert.equal(elapsed(0),"0:00");
  assert.equal(elapsed(7_400),"0:07");
  assert.equal(elapsed(92_000),"1:32");
  assert.equal(elapsed(-5),"0:00");
});

test("a wait names the device it waits for, or says your network device",()=>{
  assert.equal(waitTitle("Pixel at home"),"Waiting for Pixel at home");
  assert.equal(waitTitle("  "),"Waiting for your network device");
  assert.equal(waitTitle(null),"Waiting for your network device");
});

test("a wait explains itself and says when it is nearly over",()=>{
  assert.equal(waitDetail(5_000),"0:05 · It may be restarting, or Connect may be closed on it.");
  assert.equal(waitDetail(75_000),"1:15 · Still trying. Keep Connect open on that device.");
  assert.equal(waitDetail(WAIT_LIMIT_MS+3_000),"2:03 · Finishing the last try.");
  assert.ok(EXPLAIN_AFTER_MS<5_000,"Quick answers show nothing; a real wait is explained early");
});

test("after approval the owner sees who is finishing and how long it has taken",()=>{
  assert.equal(finishingTitle("Grandma's tablet"),"Finishing with Grandma's tablet");
  assert.equal(finishingTitle(""),"Finishing with the new device");
  assert.equal(finishingDetail(12_000),"0:12 · Approved. Waiting for it to finish joining. Keep Connect open on both devices.");
});

test("stopping a wait is told apart from a failure",()=>{
  assert.ok(stoppedWaiting(STOPPED));
  assert.ok(stoppedWaiting(new Error(STOPPED)));
  assert.ok(!stoppedWaiting("This folder is unavailable or access was not allowed"));
});
