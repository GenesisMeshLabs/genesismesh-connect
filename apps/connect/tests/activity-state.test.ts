import {test} from "node:test";
import assert from "node:assert/strict";
import {activityLabel,activityExplanation,activityCount,recoveryExplanation,exportRecordMessage,summaryAfterCheck,type ActivitySummary} from "../src/activity-state.ts";
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
    assert.equal(activityLabel(entry),"Result unconfirmed");
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
test("partial history is explicit and mobile share-sheet launch is not a claimed save",()=>{
  assert.equal(activityCount(0,false),"No access changes need attention");
  assert.match(activityCount(0,true),/older history is unavailable/);
  assert.equal(activityCount(2,true),"2 shown changes need attention");
  assert.equal(activityCount(1,false),"1 change needs attention");
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
