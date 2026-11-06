import {invoke} from "@tauri-apps/api/core";
import {el} from "./ui";
import {AdminPresentationSession} from "./host-admin-lifecycle";
import {adminDate,permissionName} from "./host-admin-state";
import {canCheckEnrollment,enrollmentCopy,enrollmentObservation,enrollmentProblem,markEnrollmentUncertain,matchesEnrollmentReadback,type EnrollmentOverview} from "./client-admin-state";

export function setupClientAdministration() {
  const dialog=el<HTMLDialogElement>("client-admin-dialog"),session=new AdminPresentationSession();
  let overview:EnrollmentOverview|null=null,busy=false,homeContext:string|undefined;
  const current=(token:number)=>dialog.open&&session.current(token);
  function problem(message:string) {el("client-admin-problem").textContent=message;el("client-admin-problem").hidden=!message;}
  function invalidate() {session.close();overview=null;busy=false;}
  function close() {invalidate();if(dialog.open)dialog.close();}
  function render() {
    el("client-admin-network").textContent=overview?.network||"Your network";
    const copy=overview?enrollmentCopy(overview):{title:busy?"Checking this device…":"Refresh to check this device",body:"Your saved network and device identity stay in place.",next:""};
    el("client-admin-state").textContent=copy.title;el("client-admin-description").textContent=copy.body;el("client-admin-next").textContent=copy.next;
    el("client-admin-details").hidden=!overview?.entry;
    const entry=overview?.entry;
    if(entry) {
      el("client-admin-host").textContent=overview!.host;
      el("client-admin-access-ends").textContent=adminDate(entry.access_ends);
      el("client-admin-request-ends").textContent=adminDate(entry.request_ends);
      el("client-admin-observed-at").textContent=entry.observed_at?adminDate(entry.observed_at):"Not yet confirmed";
      el("client-admin-history").textContent=enrollmentObservation(entry);
      el("client-admin-history").hidden=entry.status!=="uncertain";
      el("client-admin-permissions").replaceChildren(...entry.permissions.map(p=>{const li=document.createElement("li");li.textContent=permissionName(p);return li;}));
    }
    el<HTMLButtonElement>("client-admin-refresh").disabled=busy;
    el<HTMLButtonElement>("client-admin-check").disabled=busy||!canCheckEnrollment(overview);
    el("client-admin-check").hidden=!canCheckEnrollment(overview);
  }
  async function load() {
    const token=session.token();if(!current(token)||busy)return;busy=true;problem("");render();
    try {const next=await invoke<EnrollmentOverview>("client_admin_status");if(current(token))overview=next;}
    catch(error){if(current(token)){overview=null;problem(enrollmentProblem(error));}}
    finally {if(current(token)){busy=false;render();}}
  }
  async function check() {
    const token=session.token();if(!current(token)||busy||!canCheckEnrollment(overview))return;
    const expected=overview!;overview=markEnrollmentUncertain(expected);busy=true;problem("");render();
    try {const next=await invoke<EnrollmentOverview>("client_admin_check");if(current(token)){
      if(matchesEnrollmentReadback(expected,next))overview=next;
      else problem("The network or saved request changed. Close and reopen joining permissions to check the current device. The earlier result stays unconfirmed.");
    }}
    catch(error){if(current(token))problem(enrollmentProblem(error));}
    finally {if(current(token)){busy=false;render();}}
  }
  function open() {invalidate();session.open();problem("");if(!dialog.open)dialog.showModal();void load();}
  el("client-admin-open").addEventListener("click",open);
  el("client-admin-close").addEventListener("click",close);
  dialog.addEventListener("cancel",invalidate);
  dialog.addEventListener("close",()=>{if(!dialog.open)invalidate();});
  el("client-admin-refresh").addEventListener("click",()=>{invalidate();if(dialog.open){session.open();void load();}});
  el("client-admin-check").addEventListener("click",()=>void check());
  return {close,observeContext(context:string,available:boolean){if(!available||homeContext!==undefined&&homeContext!==context)close();homeContext=context;}};
}
