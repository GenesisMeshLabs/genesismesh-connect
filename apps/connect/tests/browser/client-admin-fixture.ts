// Test page only; production imports neither this harness nor these controls.
import "../../src/styles.css";
import "../../src/home.css";
import {setupClientAdministration} from "../../src/client-admin";
import type {EnrollmentOverview,EnrollmentStatus} from "../../src/client-admin-state";
const scenario=new URL(location.href).searchParams.get("scenario")||"pending";
const states=["pending","active","declined","expired","revoked","missing"];
let result=(states.includes(scenario)?scenario:"active") as EnrollmentStatus;
let network="Home network",context="native-home-context",checkContext:string|null=null,close=()=>{},observe=(value:string)=>{};
let observed:EnrollmentStatus|null=scenario==="reviewed"?null:states.includes(scenario)?result:"active";
let gateId=0;
const gates=new Map<number,{started:boolean;wait:Promise<void>;release:()=>void}>(),held=new Map<string,number[]>();
const calls:string[]=[];
const control={holdNext(command:string){let release=()=>{};const wait=new Promise<void>(resolve=>{release=resolve;});const id=++gateId;gates.set(id,{started:false,wait,release});held.set(command,[...(held.get(command)||[]),id]);return id;},
  started(id:number){return gates.get(id)?.started||false;},release(id:number){gates.get(id)?.release();},navigate(){close();},
  changeContext(value:string){context=value;network="Work network";observe(value);},setResult(value:EnrollmentStatus){result=value;},setCheckContext(value:string){checkContext=value;}};
function snapshot():EnrollmentOverview {
  const availability=["network_computer","unjoined","disconnected","unavailable"].includes(scenario)?scenario as EnrollmentOverview["availability"]:"member";
  const entry=["none","attention"].includes(scenario)||availability!=="member"?null:{request_id:"native-saved-request",status:scenario==="reviewed"?"reviewed" as const:"uncertain" as const,last_observed:observed,observed_at:observed?"2026-11-06T06:00:00Z":null,permissions:["list_pairing" as const,"approve_pairing" as const],request_ends:"2026-11-06T06:02:00Z",access_ends:"2026-11-07T06:00:00Z"};
  return {context,network,host:scenario==="unsafe"?"Hub <img src=x onerror=alert(1)>":"Home hub",availability,attention:scenario==="attention",can_check:!!entry&&scenario!=="reviewed",entry};
}
Object.assign(window,{fixtureClientCalls:calls,fixtureClientControl:control,__TAURI_INTERNALS__:{invoke:async(command:string)=>{
  calls.push(command);const id=held.get(command)?.shift(),gate=id===undefined?undefined:gates.get(id);if(gate)gate.started=true;
  let value=snapshot();
  if(command==="client_admin_check") {if(scenario!=="error"){observed=result;value={...snapshot(),context:checkContext||context,entry:{...snapshot().entry!,status:result}};}}
  else if(command!=="client_admin_status")throw Error("Fixture refuses mutation/signing/unknown IPC");
  if(gate)await gate.wait;
  if(command==="client_admin_check"&&scenario==="error")throw Error("Fixture interrupted readback");
  return structuredClone(value);
}}});
const source=new DOMParser().parseFromString(await(await fetch("/index.html")).text(),"text/html");
for(const id of ["client-admin-card","client-admin-dialog"]) {const element=source.getElementById(id)!;element.hidden=false;document.getElementById("fixture-content")!.append(element);}
const component=setupClientAdministration();component.observeContext(context,true);close=component.close;observe=value=>component.observeContext(value,true);
