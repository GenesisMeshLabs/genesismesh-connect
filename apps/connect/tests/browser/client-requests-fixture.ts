// Test page only. Production imports neither these controls nor simulated replies.
import "../../src/styles.css";import "../../src/home.css";
import {setupClientRequests} from "../../src/client-requests";
import type {RequestsOverview,RequestResult} from "../../src/client-requests-state";
const scenario=new URL(location.href).searchParams.get("scenario")||"approved";
let context="native-home-profile-key-host",network="Home network",nonce="original-nonce",digest="original-digest",mismatch="",closed=()=>{},observe=(v:string)=>{},permissionsOpened=0;
let sequence=0;const held=new Map<string,number[]>(),gates=new Map<number,{started:boolean;wait:Promise<void>;release:()=>void}>();
const calls:{command:string;args:unknown}[]=[];
const control={holdNext(command:string){let release=()=>{};const wait=new Promise<void>(r=>{release=r;});const id=++sequence;gates.set(id,{started:false,wait,release});held.set(command,[...(held.get(command)||[]),id]);return id;},started(id:number){return gates.get(id)?.started||false;},release(id:number){gates.get(id)?.release();},navigate(){closed();},changeContext(){context="native-work-profile-key-host";network="Work network";nonce="work-nonce";digest="work-digest";observe(context);},setMismatch(value:string){mismatch=value;},permissionsOpened(){return permissionsOpened;}};
function result():RequestResult {return scenario==="rejected"?{state:"rejected",waiting_name:null}:scenario==="queue"?{state:"queue_snapshot",waiting_name:"Work laptop"}:scenario==="started"?{state:"in_progress",waiting_name:null}:scenario==="unconfirmed"?{state:"unconfirmed",waiting_name:null}:{state:"approved",waiting_name:null};}
function snapshot(check=false):RequestsOverview {
 const r=result(),retained=["in_progress","unconfirmed"].includes(r.state)?scenario==="unconfirmed"?{state:"approved" as const,waiting_name:null}:null:r;
 const availability=["unavailable","unjoined","authority_host","disconnected"].includes(scenario)?scenario as RequestsOverview["availability"]:"member";
 const entry=["empty","attention"].includes(scenario)||availability!=="member"?null:{nonce,digest,operation:scenario==="rejected"?"reject_pairing" as const:scenario==="queue"?"list_pairing" as const:"approve_pairing" as const,candidate:scenario==="queue"?null:{name:scenario==="unsafe"?"Tablet <img src=x onerror=alert(1)>":"Living room tablet",comparison_code:"123456"},status:scenario==="reviewed"?"reviewed" as const:scenario==="archived"?"archived" as const:check&&retained&&!["in_progress","unconfirmed"].includes(r.state)?"observed" as const:"uncertain" as const,current_result:check?r:null,last_result:scenario==="reviewed"?null:check?r:retained,observed_at:scenario==="reviewed"?null:"2026-11-06T12:00:00Z",retained_result:scenario==="reviewed"?null:retained,retained_at:retained&&scenario!=="reviewed"?"2026-11-06T12:00:00Z":null,review_ends:"2026-11-06T12:02:00Z",access_ends:"2026-11-07T12:00:00Z"};
 return {context,network,host:scenario==="unsafe"?"Hub <img src=x onerror=alert(1)>":"Home hub",availability,attention:scenario==="attention",can_check:!!entry&&!["reviewed","archived"].includes(entry.status),entry};
}
Object.assign(window,{fixtureRequestCalls:calls,fixtureRequestControl:control,__TAURI_INTERNALS__:{invoke:async(command:string,args:Record<string,unknown>={})=>{
 calls.push({command,args});if(!["client_requests_status","client_requests_check"].includes(command)||Object.keys(args).length)throw Error("Fixture refuses mutation/signing/Execute/unknown IPC or selectors");
 const id=held.get(command)?.shift(),gate=id===undefined?undefined:gates.get(id);if(gate)gate.started=true;
 const check=command==="client_requests_check",value=snapshot(check);
 if(check&&mismatch&&value.entry){if(mismatch==="context")value.context="foreign-context";else if(mismatch==="name")value.entry.candidate!.name="Other tablet";else if(mismatch==="code")value.entry.candidate!.comparison_code="654321";else if(mismatch==="operation")value.entry.operation="reject_pairing";else if(mismatch==="nonce")value.entry.nonce="different";else value.entry.digest="different";}
 if(gate)await gate.wait;if(command==="client_requests_status"&&scenario==="load-error")throw Error("Private loader diagnostics");if(check&&scenario==="error")throw Error("Sensitive C:/private/key.json diagnostics must stay private");return structuredClone(value);
}}});
const source=new DOMParser().parseFromString(await(await fetch("/index.html")).text(),"text/html");
for(const id of ["client-admin-card","client-requests-dialog"]){const node=source.getElementById(id)!;node.hidden=false;document.getElementById("fixture-content")!.append(node);}
document.getElementById("client-admin-open")!.addEventListener("click",()=>{permissionsOpened++;});
const component=setupClientRequests();component.observeContext(context,true);closed=component.close;observe=value=>component.observeContext(value,true);
