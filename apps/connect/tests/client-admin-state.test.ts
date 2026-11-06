import {test} from "node:test";
import assert from "node:assert/strict";
import {enrollmentCopy,markEnrollmentUncertain,canCheckEnrollment,enrollmentObservation,enrollmentProblem,matchesEnrollmentReadback,type EnrollmentOverview,type EnrollmentStatus} from "../src/client-admin-state.ts";
const overview:EnrollmentOverview={context:"native-context",network:"Home",host:"Home hub",availability:"member",attention:false,can_check:true,
  entry:{request_id:"saved-id",status:"active",last_observed:"active",observed_at:"2026-11-06T06:00:00Z",permissions:["list_pairing"],request_ends:"2026-11-06T06:02:00Z",access_ends:"2026-11-07T06:00:00Z"}};
test("saved administration states explain the next action without claiming pairing execution",()=>{
  const titles:Record<EnrollmentStatus,string>={reviewed:"Saved, not sent",uncertain:"Check your saved request",pending:"Waiting for approval",active:"Approved at last check",declined:"Request declined",expired:"Request or permissions expired",revoked:"Joining permissions revoked",missing:"Request not found on the network computer"};
  for(const status of Object.keys(titles) as EnrollmentStatus[]) {
    const copy=enrollmentCopy({...overview,entry:{...overview.entry!,status}});
    assert.equal(copy.title,titles[status]);assert.ok(copy.next.length>20);
    assert.doesNotMatch(copy.body,/device was added|you can now approve|automatically retry/i);
  }
  assert.match(enrollmentCopy({...overview,entry:{...overview.entry!,status:"missing"}}).body,/may no longer retain/);
});
test("an interrupted recheck keeps previous approval as history rather than a fresh result",()=>{
  const uncertain=markEnrollmentUncertain(overview);
  assert.equal(uncertain.entry?.status,"uncertain");assert.equal(uncertain.entry?.observed_at,overview.entry?.observed_at);
  assert.equal(overview.entry?.status,"active");assert.match(enrollmentObservation(uncertain.entry!),/history, not a new permission check/);
  assert.equal(canCheckEnrollment(uncertain),true);
});
test("empty, damaged, unsent and disconnected work cannot dispatch a status check",()=>{
  for(const value of [{...overview,entry:null},{...overview,attention:true},{...overview,availability:"disconnected" as const},{...overview,availability:"unjoined" as const},{...overview,entry:{...overview.entry!,status:"reviewed" as const}},{...overview,can_check:false}])assert.equal(canCheckEnrollment(value),false);
  assert.match(enrollmentCopy({...overview,entry:null}).next,/not available/);
  assert.match(enrollmentCopy({...overview,attention:true}).body,/not replaced/);
});
test("readiness and errors preserve identity and guide recovery without raw diagnostics",()=>{
  for(const availability of ["network_computer","unjoined","disconnected","unavailable"] as const)assert.ok(enrollmentCopy({...overview,availability}).next.length>20);
  assert.match(enrollmentProblem("busy"),/Wait a moment/);
  assert.doesNotMatch(enrollmentProblem("secret path C:/private.json"),/private.json/);
  assert.match(enrollmentProblem("offline"),/saved request was not resent or replaced/);
});
test("a readback must name the current native context and exact saved request",()=>{
  assert.equal(matchesEnrollmentReadback(overview,overview),true);
  for(const value of [{...overview,context:"another-network"},{...overview,entry:{...overview.entry!,request_id:"another-request"}},{...overview,entry:null},{...overview,availability:"network_computer" as const}])assert.equal(matchesEnrollmentReadback(overview,value),false);
});
