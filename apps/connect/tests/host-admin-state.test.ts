import {test} from "node:test";
import assert from "node:assert/strict";
import {canConfirmAdmin,parseAdminReference,adminOutcomeText,adminOutcomeDetail,hostAdminProblem,permissionName,
  type AdminReference,type AdminReview,type AdminStatus,type AdminOutcome} from "../src/host-admin-state.ts";
const reference:AdminReference={review_id:"50e44b00-b80a-4acb-bd30-84c60911b014",review_digest:"review",scope:"host-scope",action:"approve",enrollment_id:"f1bb8fa7-701b-44bc-adef-29725b642300",enrollment_digest:"original-enrollment"};
const review:AdminReview={reference,network:"Home",expires_at:"2030-01-01T00:02:00Z",consequence:"Exact pairing permissions",
  device:{id:reference.enrollment_id!,device_name:"Phone",device_fingerprint:"sha256:phone",known_device:true,permissions:["list_pairing","approve_pairing"],access_ends:"2030-01-02T00:00:00Z",request_ends:"2030-01-01T00:02:00Z",decision:"pending",enrollment_digest:reference.enrollment_digest!}};
const status:AdminStatus={location:"host",mutation_ready:true,readiness:"",view:{scope:reference.scope,network:"Home",enabled:true,pending:[review.device!],administrators:[]}};
const now=Date.parse("2030-01-01T00:01:00Z");
test("approval requires native readiness, exact host scope, known device and live review",()=>{
  assert.equal(canConfirmAdmin(status,review,null,now),true);
  assert.equal(canConfirmAdmin({...status,mutation_ready:false},review,null,now),false);
  assert.equal(canConfirmAdmin({...status,view:{...status.view!,scope:"another-host"}},review,null,now),false);
  assert.equal(canConfirmAdmin(status,{...review,device:{...review.device!,known_device:false}},null,now),false);
  assert.equal(canConfirmAdmin(status,{...review,expires_at:"invalid"},null,now),false);
  assert.equal(canConfirmAdmin(status,review,null,Date.parse(review.expires_at)),false);
  assert.equal(canConfirmAdmin(status,review,reference,now),false,"unconfirmed change cannot be replayed");
});
test("readback references reject malformed, foreign-shaped and privilege-bearing input",()=>{
  assert.deepEqual(parseAdminReference(JSON.stringify(reference)),reference);
  for(const altered of [{...reference,presence:true},{...reference,action:"run_command"},{...reference,action:"__proto__"},
    {...reference,enrollment_digest:null},{...reference,scope:""},{...reference,review_id:"not-a-uuid"}])
    assert.equal(parseAdminReference(JSON.stringify(altered)),null);
  assert.equal(parseAdminReference("{"),null);
  assert.equal(parseAdminReference("x".repeat(2049)),null);
  assert.equal(parseAdminReference(JSON.stringify({...reference,action:"enable",enrollment_id:null,enrollment_digest:null}))?.action,"enable");
});
test("uncertainty, refusal and observed administrator state never imply execution or broader powers",()=>{
  const value:AdminOutcome={reference,kind:"uncertain",observed:null,detail:"No reply"};
  assert.match(adminOutcomeText(value),/not be sent again automatically/);
  assert.doesNotMatch(adminOutcomeText(value),/has the reviewed/);
  assert.match(adminOutcomeText({...value,kind:"refused"}),/not confirmed/);
  assert.match(adminOutcomeText({...value,kind:"confirmed",observed:"approved"}),/until its expiry/);
  assert.match(adminOutcomeText({...value,reference:{...reference,action:"revoke"},kind:"confirmed",observed:"revoked"}),/stays a network member/);
  assert.match(adminOutcomeText({...value,kind:"refused",observed:"revoked"}),/permissions are revoked/);
  assert.doesNotMatch(adminOutcomeText({...value,kind:"refused",observed:"revoked"}),/No change was sent|change was refused/);
  assert.equal(permissionName("list_pairing"),"See requests to join your network");
  assert.equal(permissionName("unknown" as never),"Unsupported permission");
  assert.match(adminOutcomeDetail({...value,kind:"refused",detail:"Join certificate revoked"}),/current network membership/);
  assert.match(adminOutcomeDetail({...value,kind:"refused",detail:"Authentication was canceled"}),/No change was sent/);
  assert.match(hostAdminProblem("Your network computer is busy"),/Wait a moment/);
  assert.doesNotMatch(hostAdminProblem("internal /private/path/error"),/private\/path/);
});
