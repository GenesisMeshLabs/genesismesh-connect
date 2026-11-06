import {test} from "node:test";
import assert from "node:assert/strict";
import {AdminMutations,AdminPresentationSession,adminMutationPending} from "../src/host-admin-lifecycle.ts";
import type {AdminReference,AdminOutcome} from "../src/host-admin-state.ts";
const reference:AdminReference={scope:"host",review_id:"id",review_digest:"exact",action:"approve",enrollment_id:"member",enrollment_digest:"enrollment"};
const confirmed:AdminOutcome={reference,kind:"confirmed",observed:"approved",detail:"State checked"};
test("close/navigation fence abandoned presentation while a reopened session stays current",()=>{
  const session=new AdminPresentationSession(), old=session.open();session.close();const fresh=session.open();
  assert.equal(session.current(old),false);assert.equal(session.current(fresh),true);
  session.close();assert.equal(session.current(fresh),false);
});
test("submitted mutations and eventual outcomes survive closing a presentation",()=>{
  const session=new AdminPresentationSession(), mutations=new AdminMutations();
  session.open();mutations.begin(reference);session.close();
  assert.equal(mutations.get("host")?.inFlight,true);
  assert.throws(()=>mutations.begin(reference));
  mutations.settle(reference,confirmed);session.open();
  assert.equal(mutations.get("host")?.outcome?.kind,"confirmed");
  assert.equal(mutations.get("host")?.inFlight,false);
  assert.equal(mutations.get("another-host"),undefined);
});
test("stale checks, mismatched replies and older operation completions cannot overwrite newer observations",()=>{
  const mutations=new AdminMutations();mutations.begin(reference);
  const staleRevision=mutations.beginReadback(reference),freshRevision=mutations.beginReadback(reference);
  mutations.settle(reference,confirmed);
  assert.equal(mutations.settle(reference,{...confirmed,kind:"uncertain"},staleRevision),false);
  assert.equal(mutations.settle(reference,confirmed,freshRevision),true);
  const next={...reference,review_id:"next"};mutations.begin(next);
  assert.equal(mutations.settle(reference,confirmed),false);
  mutations.settle(next,{...confirmed,reference:{...next,scope:"foreign-host"}});
  assert.equal(mutations.get("host")?.outcome?.kind,"uncertain");
  assert.throws(()=>mutations.begin({...next,review_id:"third"}));
});
test("a late submission outcome is retained without replacing a newer state observation",()=>{
  const mutations=new AdminMutations();mutations.begin(reference);
  const readback=mutations.beginReadback(reference);
  mutations.settle(reference,{...confirmed,kind:"refused",observed:"revoked"},readback);
  assert.equal(mutations.get("host")?.inFlight,true);
  assert.throws(()=>mutations.begin({...reference,review_id:"too-early"}));
  mutations.settle(reference,confirmed);
  assert.equal(mutations.get("host")?.outcome?.observed,"revoked");
  assert.equal(mutations.get("host")?.submissionOutcome?.observed,"approved");
  assert.equal(mutations.get("host")?.inFlight,false);
});

test("an older submission arriving first cannot invalidate the newer Revoked observation",()=>{
  const mutations=new AdminMutations();mutations.begin(reference);
  const readback=mutations.beginReadback(reference);
  mutations.settle(reference,confirmed);
  const record=mutations.get("host")!;
  assert.equal(record.submissionOutcome?.observed,"approved");
  assert.equal(adminMutationPending(record),true);
  assert.equal(record.outcome,null);
  assert.throws(()=>mutations.begin({...reference,review_id:"too-early"}));
  assert.equal(mutations.settle(reference,{...confirmed,kind:"refused",observed:"revoked"},readback),true);
  assert.equal(record.outcome?.observed,"revoked");
  assert.equal(record.submissionOutcome?.observed,"approved");
  assert.equal(adminMutationPending(record),false);
});

test("readback bookkeeping retains unresolved checks and requires the exact saved reference",()=>{
  const mutations=new AdminMutations();mutations.begin(reference);
  for(const mismatch of [{...reference,scope:"other"},{...reference,review_digest:"other"},{...reference,action:"revoke" as const},{...reference,enrollment_id:"other"},{...reference,enrollment_digest:"other"}]) {
    assert.throws(()=>mutations.beginReadback(mismatch));
    assert.equal(mutations.settle(mismatch,{...confirmed,reference:mismatch}),false);
  }
  const abandoned=mutations.beginReadback(reference);mutations.settle(reference,confirmed);
  assert.equal(adminMutationPending(mutations.get("host")!),true);
  const current=mutations.beginReadback(reference);
  assert.equal(mutations.settle(reference,confirmed,abandoned),false);
  assert.equal(mutations.settle(reference,{...confirmed,kind:"uncertain"},current),true);
  assert.equal(adminMutationPending(mutations.get("host")!),true);
  assert.equal(mutations.settle(reference,confirmed,current),false);
});
