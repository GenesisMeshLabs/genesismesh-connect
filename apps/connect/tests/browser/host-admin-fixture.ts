// Test page only. Never imported by startup/home or included in the app entry.
import "../../src/styles.css";
import "../../src/home.css";
import {setupHostAdministration} from "../../src/host-admin";
import type {AdminAction,AdminEntry,AdminReference,AdminReview,AdminStatus,AdminOutcome} from "../../src/host-admin-state";
const scenario=new URL(location.href).searchParams.get("scenario")||"locked";
const ready=["ready","lost","cancel","expired","off"].includes(scenario);
const scope="fixture-host-scope";
let network="Home network",navigateClose=()=>{};
let gateId=0;
const gates=new Map<number,{started:boolean;wait:Promise<void>;release:()=>void}>();
const held=new Map<string,number[]>();
const control={
  holdNext(command:string){let release=()=>{};const wait=new Promise<void>(resolve=>{release=resolve;});const id=++gateId;gates.set(id,{started:false,wait,release});held.set(command,[...(held.get(command)||[]),id]);return id;},
  started(id:number){return gates.get(id)?.started||false;},
  release(id:number){gates.get(id)?.release();},
  navigate(){navigateClose();},
  setNetwork(name:string){network=name;},
  setDecision(value:"approved"|"revoked"){decision=value;sessionStorage.setItem(`fixture.decision.${scenario}`,decision);},
};
let decision=sessionStorage.getItem(`fixture.decision.${scenario}`)||"pending";
let enabled=scenario!=="off"||sessionStorage.getItem("fixture.enabled")==="true";
const calls:string[]=JSON.parse(sessionStorage.getItem(`fixture.calls.${scenario}`)||"[]");
const entry:AdminEntry={id:"171f260e-fb3c-4aac-91c6-544ef7a56e3a",device_name:scenario==="unsafe-name"?"Phone <img src=x onerror=alert(1)>":"My phone",known_device:scenario!=="unknown",
  device_fingerprint:"sha256:26b9d89bfb11d0436abeab29dbef27af",permissions:["list_pairing","approve_pairing"],
  access_ends:new Date(Date.now()+86400000).toISOString(),request_ends:new Date(Date.now()+120000).toISOString(),decision:"pending",enrollment_digest:"fixture-enrollment-digest"};
const reviews=new Map<string,AdminReview>();
const state=():AdminStatus=>({location:"host",mutation_ready:ready,
  readiness:"Device authentication is not available for administration in this build. You can inspect requests and review changes. Enabling or changing administrator permissions stays locked.",
  view:{scope,network,enabled,pending:decision==="pending"?[entry]:[],administrators:decision==="approved"||decision==="revoked"?[{...entry,decision:decision as "approved"|"revoked"}]:[]}});
async function respond(command:string,args:Record<string,unknown>) {
  if(command==="host_admin_status")return structuredClone(state());
  if(command==="host_admin_review") {
    const query=args.query as {action:AdminAction;enrollment_id:string|null};
    const reference:AdminReference={review_id:crypto.randomUUID(),review_digest:"fixture-review-digest",scope,action:query.action,enrollment_id:query.enrollment_id,enrollment_digest:query.action==="enable"?null:entry.enrollment_digest};
    const review:AdminReview={reference,network:"Home network",device:query.action==="enable"?null:entry,
      expires_at:new Date(Date.now()+(scenario==="expired"?-1000:120000)).toISOString(),
      consequence:query.action==="enable"?"Enrolled devices may ask to manage joining devices. Each administrator still needs your approval on this computer.":query.action==="revoke"?"The device loses this pairing-administration grant on its next request. Its network membership and separately granted resource access remain in place.":"This device receives exactly the listed pairing permissions until the shown expiry. Individual resource policies still apply. You can revoke these permissions here."};
    reviews.set(reference.review_id,review);return structuredClone(review);
  }
  if(command==="host_admin_commit"||command==="host_admin_check") {
    const reference=args.reference as AdminReference;
    if(command==="host_admin_commit") {
      if(!ready||!reviews.has(reference.review_id))throw Error("Fixture refuses unsupported mutation");
      if(scenario==="cancel")return {reference,kind:"refused",observed:null,detail:"Authentication was canceled"} satisfies AdminOutcome;
      if(reference.action==="enable"){enabled=true;sessionStorage.setItem("fixture.enabled","true");}
      else {decision=reference.action==="approve"?"approved":reference.action==="revoke"?"revoked":"declined";sessionStorage.setItem(`fixture.decision.${scenario}`,decision);}
      if(scenario==="lost")throw Error("Fixture lost reply after commit");
    }
    const expected={approve:"approved",revoke:"revoked",decline:"declined",enable:null}[reference.action];
    return {reference,kind:reference.action==="enable"||decision===expected?"confirmed":"refused",observed:reference.action==="enable"?null:decision,detail:"Current state checked. This read never repeats a change."};
  }
  throw Error("Unsupported fixture command");
}
Object.assign(window,{fixtureAdminCalls:calls,fixtureAdminControl:control,__TAURI_INTERNALS__:{invoke:async(command:string,args:Record<string,unknown>={})=>{
  calls.push(command);sessionStorage.setItem(`fixture.calls.${scenario}`,JSON.stringify(calls));
  const id=held.get(command)?.shift(), gate=id===undefined?undefined:gates.get(id);
  if(gate)gate.started=true;
  let value:unknown, failure:unknown;
  try {value=await respond(command,args);}catch(error){failure=error;}
  if(gate)await gate.wait;
  if(failure)throw failure;return value;
}}});
const source=new DOMParser().parseFromString(await(await fetch("/index.html")).text(),"text/html");
for(const id of ["host-admin-card","host-admin-dialog"]) {
  const element=source.getElementById(id)!;element.hidden=false;document.getElementById("fixture-content")!.append(element);
}
navigateClose=setupHostAdministration().close;
