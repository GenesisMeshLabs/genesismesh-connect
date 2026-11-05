import { test } from "node:test";
import assert from "node:assert/strict";
import { accessOutcomeText, accessReviewLines, needsAccessCheck, type AccessRecord, type AccessOutcome } from "../src/access-state.ts";

const record:AccessRecord={
  intent:{id:"review",collection:"folder",name:"Family photos",context:{pin:{network_name:"My home",root_public_key:"root"},actor:"desktop",audience:"desktop"},
    before:{version:1,recipients:["phone-a","tablet"],expires_at:null,max_bytes:4096,max_seconds:3600,extra_gates:[]},
    after:{version:1,recipients:["phone-a","phone-b"],expires_at:null,max_bytes:2048,max_seconds:300,extra_gates:[]},expires_at:"2026-11-05T12:05:00Z"},
  digest:"bound",stage:"prepared",authorization:"not_evaluated",
};
test("review names exact network, item, allowed and removed devices, limits and expiry",()=>{
  const lines=new Map(accessReviewLines(record,[{id:"phone-a",name:"Phone"},{id:"phone-b",name:"Phone"},{id:"tablet",name:"iPad"}],true));
  assert.equal(lines.get("Network"),"My home");assert.equal(lines.get("Shared item"),"Family photos");
  assert.match(lines.get("Allowed devices")!,/Phone \(phone-a/);assert.match(lines.get("Allowed devices")!,/phone-b/);
  assert.equal(lines.get("Devices losing access"),"iPad");assert.equal(lines.get("Access ends"),"Ongoing access");
  assert.equal(lines.get("Service session limit"),"300 seconds");assert.match(lines.get("Additional rules")!,/unchanged/);
  assert.ok(lines.get("Review valid until"));
  assert.equal(new Map(accessReviewLines(record,[],false)).has("Service session limit"),false);
});
test("lost reply and submitted state offer status checking, never success or automatic retry",()=>{
  for(const stage of ["submitted","unknown"] as const){
    const outcome:AccessOutcome={record:{...record,stage,authorization:"unknown"},local_applied:false,problem:null};
    assert.equal(needsAccessCheck(outcome),true);assert.match(accessOutcomeText(outcome),/will not send it again automatically/);
    assert.doesNotMatch(accessOutcomeText(outcome),/saved and checked/);
  }
});
test("readback, core authorization, local refresh and conflicting state remain distinct",()=>{
  const outcome:AccessOutcome={record:{...record,stage:"state_observed",authorization:"unknown"},local_applied:false,problem:null};
  assert.equal(needsAccessCheck(outcome),true);assert.match(accessOutcomeText(outcome),/still needs to refresh/);
  outcome.local_applied=true;
  assert.equal(needsAccessCheck(outcome),false);assert.match(accessOutcomeText(outcome),/cannot tell which request/);
  outcome.record.authorization="core_accepted";assert.equal(accessOutcomeText(outcome),"Access saved and checked.");
  outcome.record.stage="conflict";assert.match(accessOutcomeText(outcome),/Reload the current settings/);
  assert.equal(needsAccessCheck(null),false);
});
