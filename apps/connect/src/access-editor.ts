import { invoke } from "@tauri-apps/api/core";
import { el, input } from "./ui";
import { isService, friendlyProblem, formatBytes, type HomeStatus, type HomeSpace } from "./home-state";
import { accessOutcomeText, accessReviewLines, accessPrerequisiteText, needsAccessCheck, type ResourceCapabilities, type AccessPolicy, type AccessRecord, type AccessOutcome } from "./access-state";
export function setupAccessEditor(getStatus:()=>HomeStatus|null, refresh:()=>Promise<void>, message:(s:string)=>void) {
  const dialog=el<HTMLDialogElement>("access-dialog");
  let editing:HomeSpace|null=null, policy:AccessPolicy|null=null, saving=false, originalExpiry="";
  let review:AccessRecord|null=null, outcome:AccessOutcome|null=null;
  let prerequisite="";
  function problem(value:string) {el("access-problem").textContent=value;el("access-problem").hidden=!value;}
  function selectCurrent(id:string,value:number,label:string) {
    const select=el<HTMLSelectElement>(id);
    select.querySelectorAll('[data-current]').forEach(o=>o.remove());
    if (![...select.options].some(o=>o.value===String(value))) {const option=new Option(label,String(value));option.dataset.current="true";select.add(option);}
    select.value=String(value);
  }
  async function access(space:HomeSpace) {
    const capabilities=await invoke<ResourceCapabilities>("get_resource_capabilities",{request:{collection:space.id}});
    prerequisite=accessPrerequisiteText(capabilities);
    const result=await invoke<AccessPolicy>("get_access_policy",{request:{collection:space.id}});
    policy=result;editing=space;review=null;problem("");
    outcome=await invoke<AccessOutcome|null>("access_workflow_status",{collection:space.id,check:false});
    if(outcome?.record.stage==="conflict")outcome=null; // Settings above are freshly read.
    el("access-title").textContent=`Access to ${space.name}`;
    el("access-version").textContent=`Policy version ${result.version} · Changes are enforced by your network authority.`;
    const list=el("access-devices");list.replaceChildren();
    const devices=new Map(getStatus()?.devices.map(d=>[d.id,d.name]) || []);
    // Retain existing grants even if the current member list is temporarily stale.
    for(const id of result.recipients) if(!devices.has(id)) devices.set(id,"Previously allowed device (refresh Devices to identify)");
    for(const [id,name] of devices) {
      const label=document.createElement("label"), box=document.createElement("input");
      box.type="checkbox";box.name="access-recipient";box.value=id;box.checked=result.recipients.includes(id);
      label.append(box,document.createTextNode(name));list.append(label);
    }
    if(result.expires_at) {
      const date=new Date(result.expires_at);date.setMinutes(date.getMinutes()-date.getTimezoneOffset());input("access-expiry").value=date.toISOString().slice(0,16);
    } else input("access-expiry").value="";
    originalExpiry=input("access-expiry").value;
    selectCurrent("access-size",result.max_bytes,`Current limit: ${formatBytes(result.max_bytes)}`);
    selectCurrent("access-duration",result.max_seconds,`Current limit: ${result.max_seconds} seconds`);
    el("access-duration-field").hidden=!isService(space);
    input("access-extra").value=JSON.stringify(result.extra_gates,null,2);
    render();
    if(!dialog.open)dialog.showModal();
  }
  function render() {
    el("access-prerequisite").textContent=prerequisite;el("access-prerequisite").hidden=!prerequisite;
    el("access-description").textContent=prerequisite ? "View this item’s current access settings." : "Choose who can use this item. You’ll review the change before it is saved.";
    el("access-choices").querySelectorAll<HTMLInputElement|HTMLTextAreaElement|HTMLSelectElement>("input,textarea,select").forEach(field=>{field.disabled=!!prerequisite;});
    el("access-choices").hidden=!!review||needsAccessCheck(outcome);
    el("access-review").hidden=!review;
    el("access-outcome").hidden=!outcome;
    el("access-outcome-text").textContent=outcome ? accessOutcomeText(outcome) : "";
    el<HTMLButtonElement>("access-check").hidden=!outcome || outcome.record.stage==="conflict";
    el<HTMLButtonElement>("access-reload").hidden=!outcome || needsAccessCheck(outcome);
    el<HTMLButtonElement>("access-save").disabled=saving||!!prerequisite||needsAccessCheck(outcome)||outcome?.record.stage==="conflict";
    el<HTMLButtonElement>("access-save").textContent=review ? "Confirm access change" : "Review change";
    el<HTMLButtonElement>("access-back").disabled=saving;
    el<HTMLButtonElement>("access-check").disabled=saving;
    el<HTMLButtonElement>("access-reload").disabled=saving;
    if(review) {
      const list=el("access-review-lines");list.replaceChildren();
      for(const [label,value] of accessReviewLines(review,getStatus()?.devices||[],!!editing&&isService(editing))) {
        const dt=document.createElement("dt"),dd=document.createElement("dd");dt.textContent=label;dd.textContent=value;list.append(dt,dd);
      }
      el("access-review-exact").textContent=JSON.stringify(review.intent,null,2);
    }
  }
  async function cancelReview() {
    const pending=review;
    if(pending)await invoke("cancel_access_review",{id:pending.intent.id});
    if(review===pending)review=null;render();window.dispatchEvent(new Event("connect-access-history-changed"));
  }
  el("access-close").addEventListener("click",()=>{if(!saving){void cancelReview().catch(()=>{});dialog.close();}});
  el("access-back").addEventListener("click",()=>{if(!saving)void cancelReview().catch(e=>problem(friendlyProblem(String(e))));});
  el("access-check").addEventListener("click",async()=>{
    if(saving||!editing)return;saving=true;problem("");render();
    try{
      outcome=await invoke<AccessOutcome|null>("access_workflow_status",{collection:editing.id,check:true,workflowId:outcome?.record.intent.id||null});
      window.dispatchEvent(new Event("connect-access-history-changed"));
      if(outcome?.record.stage==="state_observed"&&outcome.local_applied){dialog.close();message(accessOutcomeText(outcome));}
      await refresh();
    }
    catch(e){problem(friendlyProblem(String(e)));}finally{saving=false;render();}
  });
  el("access-reload").addEventListener("click",()=>{if(!saving&&editing)void access(editing).catch(e=>problem(friendlyProblem(String(e))));});
  dialog.addEventListener("cancel",e=>{if(saving)e.preventDefault();else void cancelReview().catch(()=>{});});
  el("access-form").addEventListener("submit",async e=>{
    e.preventDefault();if(saving||prerequisite||!editing||!policy||needsAccessCheck(outcome))return;problem("");
    if(review) {
      const approved=review;saving=true;render();
      try {
        outcome=await invoke<AccessOutcome>("commit_access_policy",{request:{id:approved.intent.id,digest:approved.digest}});
        window.dispatchEvent(new Event("connect-access-history-changed"));
        review=null;
        if(outcome.record.stage==="state_observed"&&outcome.local_applied){dialog.close();message(accessOutcomeText(outcome));}
        await refresh();
      }catch(error){
        // A lost native reply may follow dispatch. Keep the stored workflow ID
        // and show read-only reconciliation rather than offering Send again.
        review=null;
        outcome={record:{...approved,stage:"unknown",authorization:"unknown"},local_applied:false,problem:null};
        try {
          const known=await invoke<AccessOutcome|null>("access_workflow_status",{collection:editing.id,check:false,workflowId:approved.intent.id});
          if(known?.record.stage==="prepared") {review=known.record;outcome=null;}
          else if(known)outcome=known;
        }catch{/* Preserve uncertainty. */}
        problem(needsAccessCheck(outcome) ? "The response is unconfirmed. Use Check status to find out what happened." : friendlyProblem(String(error)));
      }finally{saving=false;render();}
      return;
    }
    const recipients=[...dialog.querySelectorAll<HTMLInputElement>('input[name="access-recipient"]:checked')].map(b=>b.value);
    if(!recipients.length){problem("Choose at least one device, or use Stop sharing to close access for everyone.");return;}
    let extra_gates:unknown;
    try{extra_gates=JSON.parse(input("access-extra").value);}catch{problem("Additional rules must be a valid JSON array.");return;}
    if(!Array.isArray(extra_gates)){problem("Additional rules must be a JSON array.");return;}
    let expires_at:string|null=null;
    if(input("access-expiry").value){const date=new Date(input("access-expiry").value);if(!Number.isFinite(date.getTime())||date.getTime()<=Date.now()){problem("Choose a future expiry date.");return;}expires_at=date.toISOString();}
    if(input("access-expiry").value===originalExpiry) expires_at=policy.expires_at;
    saving=true;render();
    try {
      review=await invoke<AccessRecord>("review_access_policy",{request:{collection:editing.id,settings:{...policy,recipients,expires_at,max_bytes:Number(el<HTMLSelectElement>("access-size").value),max_seconds:Number(el<HTMLSelectElement>("access-duration").value),extra_gates}}});
      window.dispatchEvent(new Event("connect-access-history-changed"));
      outcome=null;
      render();el<HTMLButtonElement>("access-save").focus();
    }catch(error){problem(friendlyProblem(String(error)));}
    finally{saving=false;render();}
  });
  return access;
}
