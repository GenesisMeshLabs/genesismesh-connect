import {test} from "node:test";
import assert from "node:assert/strict";
import {availability,recoveryReminder,recoveryStatus,restoredMessage} from "../src/setup-state.ts";

test("starting a network says where it runs and when others reach it",()=>{
  const phone=availability("phone");
  assert.match(phone.where,/while Connect is open on this phone/);
  assert.match(phone.where,/two minutes after you leave Connect/);
  assert.match(phone.alwaysOn,/computer you keep on, or a home server/);
  const computer=availability("computer");
  assert.match(computer.where,/while this computer is on and Connect is open/);
  assert.match(computer.alwaysOn,/home server/);
});

test("only the device that runs the network is reminded, until a file is saved",()=>{
  assert.equal(recoveryReminder(true,true,null),true);
  assert.equal(recoveryReminder(true,true,"2026-11-09T10:00:00Z"),false);
  assert.equal(recoveryReminder(false,true,null),false,"A joined device has no recovery file to save");
  assert.equal(recoveryReminder(true,false,null),false,"Nothing to save before the network exists");
});

test("the recovery row says whether and when a file was saved",()=>{
  const now=new Date("2026-11-09T12:00:00Z");
  assert.match(recoveryStatus(null,now),/^Not saved yet/);
  assert.match(recoveryStatus("2026-11-09T08:00:00Z",now),/^Last saved today/);
  assert.match(recoveryStatus("2026-11-08T08:00:00Z",now),/^Last saved yesterday/);
  assert.match(recoveryStatus("2026-10-30T08:00:00Z",now),/^Last saved 10 days ago/);
  assert.equal(recoveryStatus("not a date",now),"Brings this network back on another device");
});

test("after a restore Connect says what the recovery file cannot bring back",()=>{
  const said=restoredMessage("2026-10-30T09:00:00Z","en-GB");
  assert.match(said,/as it was on 30 October 2026/);
  assert.match(said,/devices that joined later must join again/);
  assert.match(said,/devices you removed later may have access again/);
  assert.match(said,/Don't run this network on the old device again/);
  assert.match(restoredMessage("garbled"),/when its recovery file was saved/);
});
