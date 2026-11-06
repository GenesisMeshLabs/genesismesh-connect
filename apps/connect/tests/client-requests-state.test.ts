import {test} from "node:test";
import assert from "node:assert/strict";
import {canCheckRequest,matchesRequestReadback,requestConfirmed,requestUncertain,requestsCopy,requestHistory,requestsProblem,type RequestsOverview} from "../src/client-requests-state.ts";
const result={state:"approved" as const,waiting_name:null};
const value:RequestsOverview={context:"native-profile-host-key",network:"Home network",host:"Home hub",availability:"member",attention:false,can_check:true,entry:{nonce:"original-nonce",digest:"original-digest",operation:"approve_pairing",candidate:{name:"Living room tablet",comparison_code:"123456"},status:"observed",current_result:result,last_result:result,observed_at:"2026-11-06T12:00:00Z",retained_result:result,retained_at:"2026-11-06T12:00:00Z",review_ends:"2026-11-06T12:02:00Z",access_ends:"2026-11-07T12:00:00Z"}};
test("confirmed display needs a fresh correctly typed result and retained evidence",()=>{
 assert.equal(requestConfirmed(value),true);assert.equal(requestsCopy(value).title,"Approval confirmed at last check");
 for(const entry of [{...value.entry!,current_result:null},{...value.entry!,retained_result:null},{...value.entry!,current_result:{state:"rejected" as const,waiting_name:null}},{...value.entry!,observed_at:null},{...value.entry!,status:"uncertain" as const}]) {
  assert.equal(requestConfirmed({...value,entry}),false);assert.notEqual(requestsCopy({...value,entry}).title,"Approval confirmed at last check");
 }
});
test("interruption retains old evidence and removes current confirmation without changing the source",()=>{
 const uncertain=requestUncertain(value);assert.equal(uncertain.entry?.current_result,null);assert.equal(uncertain.entry?.status,"uncertain");
 assert.deepEqual(uncertain.entry?.retained_result,result);assert.equal(value.entry?.status,"observed");assert.match(requestHistory(uncertain.entry!),/history, not a new confirmation/);
 assert.equal(requestsCopy(uncertain).title,"Check this device request");assert.equal(canCheckRequest(uncertain),true);
});
test("status checking cannot send reviewed, archived, missing, unavailable or damaged work",()=>{
 for(const v of [{...value,entry:null},{...value,attention:true},{...value,can_check:false},{...value,availability:"unavailable" as const},{...value,availability:"disconnected" as const},{...value,availability:"unjoined" as const},{...value,availability:"authority_host" as const},{...value,entry:{...value.entry!,status:"reviewed" as const}},{...value,entry:{...value.entry!,status:"archived" as const}}]) assert.equal(canCheckRequest(v),false);
});
test("readback must preserve the exact native context, action, candidate and original reference",()=>{
 assert.equal(matchesRequestReadback(value,value),true);
 for(const changed of [{...value,context:"foreign-profile"},{...value,entry:null},{...value,attention:true},{...value,entry:{...value.entry!,nonce:"replacement"}},{...value,entry:{...value.entry!,digest:"replacement"}},{...value,entry:{...value.entry!,operation:"reject_pairing" as const}},{...value,entry:{...value.entry!,candidate:{name:"Another tablet",comparison_code:"123456"}}},{...value,entry:{...value.entry!,candidate:{name:"Living room tablet",comparison_code:"654321"}}}])assert.equal(matchesRequestReadback(value,changed),false);
});
test("each readiness state explains a next step and never offers a mutation",()=>{
 for(const availability of ["unavailable","unjoined","authority_host","disconnected"] as const){const text=requestsCopy({...value,availability});assert.ok(text.next.length>15);}
 assert.equal(requestsCopy({...value,entry:null}).title,"No saved device request");assert.equal(requestsCopy({...value,attention:true}).title,"Saved request needs attention");
 assert.equal(requestsCopy({...value,entry:{...value.entry!,status:"reviewed",current_result:null,retained_result:null,last_result:null}}).title,"Saved, not sent");
});
test("a confirmed original queue result stays a saved snapshot, not a current pending-device claim",()=>{
 const queue={state:"queue_snapshot" as const,waiting_name:"Work laptop"};const view={...value,entry:{...value.entry!,operation:"list_pairing" as const,candidate:null,current_result:queue,retained_result:queue}};
 assert.equal(requestConfirmed(view),true);assert.match(requestsCopy(view).body,/was waiting/);assert.match(requestsCopy(view).next,/saved snapshot/);
 assert.equal(requestConfirmed({...view,entry:{...view.entry,retained_result:{...queue,waiting_name:"Other laptop"}}}),false);
});
test("started, unknown and errors preserve uncertainty and do not leak raw diagnostics",()=>{
 for(const state of ["in_progress","unconfirmed"] as const) {const copy=requestsCopy({...requestUncertain(value),entry:{...requestUncertain(value).entry!,current_result:{state,waiting_name:null}}});assert.match(copy.next,/original|not send/);}
 assert.doesNotMatch(requestsProblem("C:/private/admin-key.json secret"),/private|admin-key|secret/);assert.match(requestsProblem("busy"),/Wait a moment/);
});


test("an expired unsent archive never implies a checked or executed result",()=>{
 const view={...value,can_check:false,entry:{...value.entry!,status:"archived" as const,current_result:null,last_result:null,observed_at:null,retained_result:null,retained_at:null}};
 assert.equal(requestsCopy(view).title,"Expired request closed");assert.match(requestsCopy(view).body,/before it was sent/);
 assert.equal(canCheckRequest(view),false);assert.equal(requestConfirmed(view),false);
});
