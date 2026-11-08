import {test} from "node:test";
import assert from "node:assert/strict";
import {whenText,activityDay,activityGroups,activityRowDetail,activityLabel,activityExplanation,recoveryExplanation,exportRecordMessage,summaryAfterCheck,type ActivitySummary} from "../src/activity-state.ts";
import type {AccessOutcome} from "../src/access-state.ts";

test("activity distinguishes an acknowledged change from unattributed matching state",()=>{
  const accepted={stage:"state_observed" as const,authorization:"core_accepted" as const};
  const uncertain={stage:"state_observed" as const,authorization:"unknown" as const};
  assert.equal(activityLabel(accepted),"Access update checked");
  assert.equal(activityLabel(uncertain),"Matching settings observed");
  assert.match(activityExplanation(accepted),/does not show whether a file or service was used/);
  assert.match(activityExplanation(uncertain),/cannot identify which request/);
});
test("unconfirmed and conflicting records never claim failure, receipt verification or resource use",()=>{
  for(const stage of ["submitted","unknown"] as const){
    const entry={stage,authorization:"unknown" as const};
    assert.equal(activityLabel(entry),"Not confirmed yet");
    assert.match(activityExplanation(entry),/will not send it again automatically/);
    assert.doesNotMatch(activityExplanation(entry),/failed|verified receipt|downloaded/);
  }
  assert.equal(activityLabel({stage:"conflict",authorization:"unknown"}),"Settings changed");
  assert.match(activityExplanation({stage:"prepared",authorization:"not_evaluated"}),/Nothing was sent/);
  assert.match(activityLabel({stage:"cancelled",authorization:"not_evaluated"}),/before sending/);
});
test("recovery hints preserve offline history, old host boundaries and immutable archive semantics",()=>{
  assert.match(recoveryExplanation("disconnected"),/history remains available/);
  assert.match(recoveryExplanation("previous_host"),/previous network computer/);
  assert.match(recoveryExplanation("item_stopped"),/no longer shared/);
  assert.match(recoveryExplanation("archived"),/cannot approve or resend/);
  assert.match(recoveryExplanation("check_status"),/without sending/);
});
test("a mobile share-sheet launch is not a claimed save",()=>{
  assert.match(exportRecordMessage("saved"),/unsigned workflow history/);
  assert.equal(exportRecordMessage("share_sheet_opened"),"Choose where to save or share the local record.");
  assert.doesNotMatch(exportRecordMessage("share_sheet_opened"),/saved|success/);
  assert.equal(exportRecordMessage("cancelled"),"Saving cancelled.");
});

test("a checked record removed from the attention filter updates its open detail without claiming attribution",()=>{
  const entry={stage:"unknown",authorization:"unknown",needs_attention:true,recovery:"check_status",policy_observed:null} as ActivitySummary;
  const outcome={record:{stage:"state_observed",authorization:"unknown",updated_at:"2026-11-05T16:00:00Z",observed:{version:2}}} as AccessOutcome;
  const next=summaryAfterCheck(entry,outcome);
  assert.equal(next.needs_attention,false);assert.equal(next.recovery,"settled");
  assert.equal(next.policy_observed,2);assert.equal(next.authorization,"unknown");
  assert.equal(activityLabel(next),"Matching settings observed");
});
test("activity times read as today, yesterday or a short date",()=>{
  const now=new Date(2026,10,7,15,30);
  assert.match(whenText(new Date(2026,10,7,1,13).toISOString(),now),/^Today, /);
  assert.match(whenText(new Date(2026,10,6,23,59).toISOString(),now),/^Yesterday, /);
  const older=whenText(new Date(2026,10,1,9,0).toISOString(),now);
  assert.doesNotMatch(older,/Today|Yesterday|2026/);assert.match(older,/1/);
  assert.match(whenText(new Date(2025,10,1,9,0).toISOString(),now),/2025/,"Another year is named");
});
test("activity groups into today, yesterday and earlier, keeping each day's order",()=>{
  const now=new Date(2026,10,8,9,0);
  const at=(d:number,h:number)=>new Date(2026,10,d,h,0).toISOString();
  assert.equal(activityDay(at(8,0),now),"Today");
  assert.equal(activityDay(new Date(2026,10,8,23,0).toISOString(),now),"Today","A later clock is not a future day");
  assert.equal(activityDay(new Date(2026,10,9,1,0).toISOString(),now),"Today","A clock ahead of this one counts as today");
  assert.equal(activityDay(at(7,23),now),"Yesterday");
  assert.equal(activityDay(at(6,23),now),"Earlier");
  const entries=[{id:"a",created_at:at(8,8)},{id:"b",created_at:at(5,1)},{id:"c",created_at:at(8,7)},{id:"d",created_at:at(1,1)}];
  assert.deepEqual(activityGroups(entries,now).map(g=>[g.day,g.entries.map(e=>e.id)]),[["Today",["a","c"]],["Earlier",["b","d"]]]);
  assert.deepEqual(activityGroups([],now),[]);
});
test("an activity row says what happened and when, without repeating the day",()=>{
  const now=new Date(2026,10,8,9,0);
  const today=activityRowDetail({stage:"unknown",authorization:"unknown",created_at:new Date(2026,10,8,8,5).toISOString()},now);
  assert.match(today,/^Not confirmed yet · /);assert.doesNotMatch(today,/Today/);
  const yesterday=activityRowDetail({stage:"state_observed",authorization:"core_accepted",created_at:new Date(2026,10,7,8,5).toISOString()},now);
  assert.match(yesterday,/^Access update checked · /);assert.doesNotMatch(yesterday,/Yesterday/);
  const earlier=activityRowDetail({stage:"conflict",authorization:"unknown",created_at:new Date(2026,10,2,8,5).toISOString()},now);
  assert.match(earlier,/^Settings changed · .*2/);
});
