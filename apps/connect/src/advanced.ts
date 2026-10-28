import { invoke } from "@tauri-apps/api/core";
import { record } from "./activity";
import { advancedGuidance, connectionFailure, type EverydayView } from "./advanced-state";
import type { HomeStatus } from "./home-state";
import { el } from "./ui";
import "./advanced.css";

export function setupAdvanced(getStatus:()=>HomeStatus|null, refresh:()=>Promise<void>, goHome:(view:EverydayView,anchor?:string)=>void) {
  let checking=false, selecting=false, context="";
  function render() {
    const status=getStatus(), guidance=advancedGuidance(status);
    el("help-context").hidden=!!status&&status.configured&&!status.disconnected&&!status.leaving&&!status.problem&&status.devices.length>0;
    el("help-status-title").textContent=guidance.title;
    el("help-status-detail").textContent=guidance.detail;
    el("help-next-action").textContent=guidance.action;
    el("help-check-device").textContent=guidance.selected;
    el<HTMLButtonElement>("help-check").disabled=checking||selecting||!guidance.canCheck;
    const select=el<HTMLSelectElement>("help-device-select");
    select.disabled=checking||selecting||!status?.configured||!!status.disconnected||!!status.leaving;
    if(!selecting) {
      const stamp=JSON.stringify([status?.devices,status?.selected_device]);
      if(select.dataset.state!==stamp){
        const placeholder=new Option("Choose a saved device", "");placeholder.disabled=!!status?.devices.length;
        select.replaceChildren(placeholder);
        for(const device of new Map(status?.devices.map(d=>[d.id,d])||[]).values())select.add(new Option(device.name,device.id));
        select.dataset.state=stamp;
      }
      select.value=status?.selected_device||"";
    }
    el("help-check-prerequisite").hidden=guidance.canCheck;
    el("help-check-prerequisite").textContent=guidance.checkHint;
    const next=JSON.stringify([status?.configured,status?.network,status?.selected_device,status?.disconnected,status?.leaving]);
    if(context!==next) {context=next;el("help-check-result").hidden=true;el<HTMLDetailsElement>("help-check-details").open=false;}
    el("help-recovery-action").hidden=!status?.owner;
  }
  el("help-next-action").addEventListener("click",()=>goHome(advancedGuidance(getStatus()).view));
  el("advanced-shell").addEventListener("click",event=>{
    const button=(event.target as HTMLElement).closest<HTMLButtonElement>("[data-home-view]");
    const view=button?.dataset.homeView;
    if(view&&["files","devices","settings"].includes(view)) goHome(view as EverydayView,button?.dataset.homeAnchor);
  });
  el("help-show-experts").addEventListener("click",()=>{
    el<HTMLDetailsElement>("expert-tools").open=true;el("device-tab").focus();
  });
  el("help-device-select").addEventListener("change",async()=>{
    const id=el<HTMLSelectElement>("help-device-select").value;
    if(!id){render();return;}
    if(checking||selecting)return;
    selecting=true;render();el("help-select-problem").hidden=true;
    try{await invoke("select_device",{id});}
    catch{el("help-select-problem").hidden=false;}
    finally{try{await refresh();}catch{/* A later status refresh can retry. */}selecting=false;render();}
  });
  el("help-check").addEventListener("click",async()=>{
    if(checking||selecting||!advancedGuidance(getStatus()).canCheck)return;
    checking=true;render();const checkedContext=context;
    el("help-check-result").hidden=false;el("help-check-outcome").textContent="Checking your saved device…";
    el("help-check-advice").textContent="Keep Connect open on both devices.";
    el("help-check-time").textContent="";el("help-check-details").hidden=true;
    try {
      await invoke("check_connection");
      if(context!==checkedContext)return;
      el("help-check-outcome").textContent="Your saved device replied";
      el("help-check-advice").textContent="The encrypted connection and device identity were checked. Each file or service request still uses its own access policy.";
      record("Saved-device connection check","success","Device identity and encrypted round trip checked; resource permissions are separate.");
    } catch(error) {
      if(context!==checkedContext)return;
      const outcome=connectionFailure(String(error));
      el("help-check-outcome").textContent=outcome.title;el("help-check-advice").textContent=outcome.detail;
      el("help-check-error").textContent=String(error);el("help-check-details").hidden=false;
      record("Saved-device connection check","error");
    } finally {
      checking=false;
      if(context===checkedContext)el("help-check-time").textContent=`Checked at ${new Date().toLocaleTimeString()}`;
      try{await refresh();}catch{/* Preserve the explicit check result if a later status read fails. */}
      render();
    }
  });
  el("help-show-failures").addEventListener("click",()=>{
    const filter=el<HTMLSelectElement>("activity-filter");filter.value="error";filter.dispatchEvent(new Event("change"));
  });
  render();return {render};
}
