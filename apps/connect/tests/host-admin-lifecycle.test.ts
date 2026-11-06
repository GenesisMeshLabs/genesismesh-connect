import {test} from "node:test";
import assert from "node:assert/strict";
import {AdminMutations,AdminPresentationSession} from "../src/host-admin-lifecycle.ts";
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
  const mutations=new AdminMutations();const first=mutations.begin(reference);const staleRevision=first.revision;
  mutations.settle(reference,confirmed);
  assert.equal(mutations.settle(reference,{...confirmed,kind:"uncertain"},staleRevision),false);
  const next={...reference,review_id:"next"};mutations.begin(next);
  assert.equal(mutations.settle(reference,confirmed),false);
  mutations.settle(next,{...confirmed,reference:{...next,scope:"foreign-host"}});
  assert.equal(mutations.get("host")?.outcome?.kind,"uncertain");
  assert.throws(()=>mutations.begin({...next,review_id:"third"}));
});
test("a late submission outcome is retained without replacing a newer state observation",()=>{
  const mutations=new AdminMutations();mutations.begin(reference);
  mutations.settle(reference,{...confirmed,kind:"refused",observed:"revoked"},0);
  assert.equal(mutations.get("host")?.inFlight,true);
  assert.throws(()=>mutations.begin({...reference,review_id:"too-early"}));
  mutations.settle(reference,confirmed);
  assert.equal(mutations.get("host")?.outcome?.observed,"revoked");
  assert.equal(mutations.get("host")?.submissionOutcome?.observed,"approved");
  assert.equal(mutations.get("host")?.inFlight,false);
});
