import {invoke} from "@tauri-apps/api/core";
import {el} from "./ui";
import {AdminPresentationSession} from "./host-admin-lifecycle";
import {adminDate} from "./host-admin-state";
import {canCheckRequest,matchesRequestReadback,requestedAction,requestHistory,requestsCopy,requestsProblem,requestUncertain,type RequestsOverview} from "./client-requests-state";
export function setupClientRequests() {
  const dialog=el<HTMLDialogElement>("client-requests-dialog"),session=new AdminPresentationSession();
  let overview:RequestsOverview|null=null,busy=false,homeContext:string|undefined;
  const current=(token:number)=>dialog.open&&session.current(token);
  function problem(message:string){el("client-requests-problem").textContent=message;el("client-requests-problem").hidden=!message;}
  function invalidate(){session.close();overview=null;busy=false;}
  function close(){invalidate();if(dialog.open)dialog.close();}
  function render(){
    const copy=overview?requestsCopy(overview):{title:busy?"Checking this device...":"Could not read this device",body:busy?"Looking for a saved device request.":"Refresh this device to look for its saved request.",next:""};
    el("client-requests-network").textContent=overview?.network||"Your network";
    el("client-requests-state").textContent=copy.title;el("client-requests-description").textContent=copy.body;el("client-requests-next").textContent=copy.next;
    const entry=overview?.entry;
    el("client-requests-details").hidden=!entry;
    if(entry){
      el("client-requests-action").textContent=requestedAction(entry);
      el("client-requests-host").textContent=overview!.host;
      el("client-requests-code-row").hidden=!entry.candidate;
      el("client-requests-code").textContent=entry.candidate?.comparison_code||"";
      el("client-requests-observed").textContent=entry.observed_at?adminDate(entry.observed_at):"Not yet confirmed";
      el("client-requests-access-ends").textContent=adminDate(entry.access_ends);
      el("client-requests-history").textContent=requestHistory(entry);
      el("client-requests-retained-at").textContent=entry.retained_at?`Recorded at ${adminDate(entry.retained_at)}`:"";
    }
    const check=el<HTMLButtonElement>("client-requests-check");check.hidden=!canCheckRequest(overview);check.disabled=busy||!canCheckRequest(overview);
    el<HTMLButtonElement>("client-requests-refresh").disabled=busy;
  }
  async function load(){
    const token=session.token();if(!current(token)||busy)return;
    if(overview)overview=requestUncertain(overview);busy=true;problem("");render();
    try{const next=await invoke<RequestsOverview>("client_requests_status");if(current(token))overview=next;}
    catch(error){if(current(token)){problem(requestsProblem(error));}}
    finally{if(current(token)){busy=false;render();}}
  }
  async function check(){
    const token=session.token();if(!current(token)||busy||!canCheckRequest(overview))return;
    const expected=overview!;overview=requestUncertain(expected);busy=true;problem("");render();
    try{const next=await invoke<RequestsOverview>("client_requests_check");if(current(token)){
      if(matchesRequestReadback(expected,next))overview=next;
      else problem("The network or saved request changed. Refresh this device to check its current request. The earlier result remains unconfirmed.");
    }}catch(error){if(current(token))problem(requestsProblem(error));}
    finally{if(current(token)){busy=false;render();}}
  }
  function open(){invalidate();session.open();problem("");if(!dialog.open)dialog.showModal();void load();}
  el("client-requests-permissions").addEventListener("click",()=>{close();el<HTMLButtonElement>("client-admin-open").click();});
  el("client-requests-open").addEventListener("click",open);el("client-requests-close").addEventListener("click",close);
  dialog.addEventListener("cancel",invalidate);dialog.addEventListener("close",()=>{if(!dialog.open)invalidate();});
  el("client-requests-refresh").addEventListener("click",()=>void load());el("client-requests-check").addEventListener("click",()=>void check());
  return {close,observeContext(context:string,available:boolean){if(!available||homeContext!==undefined&&homeContext!==context)close();homeContext=context;}};
}
