import {invoke} from "@tauri-apps/api/core";
import {el} from "./ui";
import {AdminMutations,AdminPresentationSession} from "./host-admin-lifecycle";
import {adminActionNames,adminDate,adminOutcomeText,adminOutcomeDetail,hostAdminProblem,canConfirmAdmin,parseAdminReference,permissionName,
  type AdminAction,type AdminEntry,type AdminOutcome,type AdminReference,type AdminReview,type AdminStatus} from "./host-admin-state";

export function setupHostAdministration() {
  const dialog=el<HTMLDialogElement>("host-admin-dialog");
  let status:AdminStatus|null=null, review:AdminReview|null=null, outcome:AdminOutcome|null=null;
  let pending:AdminReference|null=null, busy=false, storageProblem=false;
  const presentation=new AdminPresentationSession(), mutations=new AdminMutations();
  const current=(token:number)=>dialog.open&&presentation.current(token);
  const storageKey=(scope:string)=>`connect.host-admin.check.v1.${scope}`;
  function problem(message:string) {el("host-admin-problem").textContent=message;el("host-admin-problem").hidden=!message;}
  function saveReference(scope:string,value:AdminReference|null) {
    try {if(value)localStorage.setItem(storageKey(scope),JSON.stringify(value));else localStorage.removeItem(storageKey(scope));}
    catch {storageProblem=true;}
  }
  function syncMutation(scope:string) {
    let record=mutations.get(scope);
    if(!record) {
      try {
        const raw=localStorage.getItem(storageKey(scope)), saved=parseAdminReference(raw);
        if(saved?.scope===scope)record=mutations.restore(saved);
        else if(raw)storageProblem=true;
      } catch {storageProblem=true;}
    }
    outcome=record?.outcome||null;
    pending=record&&(record.inFlight||!record.outcome||record.outcome.kind==="uncertain")?record.reference:null;
  }
  function settleMutation(reference:AdminReference,value:AdminOutcome,expectedRevision?:number) {
    if(!mutations.settle(reference,value,expectedRevision))return;
    const record=mutations.get(reference.scope)!;
    saveReference(reference.scope,record.inFlight||!record.outcome||record.outcome.kind==="uncertain"?reference:null);
    // Mutation bookkeeping survives a closed session. It may update only the
    // matching observation, never an abandoned review or another host's view.
    if(dialog.open&&status?.view?.scope===reference.scope&&pending?.review_id===reference.review_id) {
      syncMutation(reference.scope);render();
    }
  }
  function invalidatePresentation() {
    presentation.close();busy=false;review=null;status=null;outcome=null;pending=null;
  }
  function close() {invalidatePresentation();if(dialog.open)dialog.close();}
  function open() {
    invalidatePresentation();presentation.open();problem("");if(!dialog.open)dialog.showModal();void load();
  }
  function restart() {invalidatePresentation();if(dialog.open){presentation.open();void load();}}
  function node<K extends keyof HTMLElementTagNameMap>(tag:K,text:string,className="") {
    const value=document.createElement(tag);value.textContent=text;value.className=className;return value;
  }
  function permissionList(entry:AdminEntry) {
    const list=document.createElement("ul");
    for(const permission of entry.permissions)list.append(node("li",permissionName(permission)));
    return list;
  }
  function entryCard(entry:AdminEntry,isPending:boolean) {
    const card=node("article","","host-admin-entry");
    card.append(node("h3",entry.device_name),node("p",`Device ${entry.device_fingerprint.slice(-12)} · ${entry.decision}`,"home-muted"));
    card.append(permissionList(entry),node("p",`Permissions end ${adminDate(entry.access_ends)}`));
    if(isPending)card.append(node("p",`Request expires ${adminDate(entry.request_ends)}`,"home-muted"));
    const details=document.createElement("details");details.append(node("summary","Device details"),node("p",`Device fingerprint: ${entry.device_fingerprint}`,"host-admin-fingerprint"));card.append(details);
    if(!entry.known_device)card.append(node("p","Identify this member in Devices before approving administration.","host-admin-notice"));
    const actions=node("div","","button-row");
    for(const action of (isPending ? ["approve","decline"] : entry.decision==="approved" ? ["revoke"] : []) as AdminAction[]) {
      const button=node("button",action==="approve"?"Review request":action==="decline"?"Review decline":"Review revocation","secondary");
      button.disabled=busy||!!pending||(action==="approve"&&!entry.known_device);
      button.addEventListener("click",()=>void prepare(action,entry.id));actions.append(button);
    }
    card.append(actions);return card;
  }
  function render() {
    const view=status?.view;
    el("host-admin-network").textContent=view?.network || "Your network";
    el("host-admin-readiness").textContent=status?.readiness || (busy?"Checking this computer…":"Administrator setup is unavailable. Refresh to check this computer.");
    el("host-admin-readiness").hidden=!!status?.mutation_ready;
    el("host-admin-overview").hidden=!!review;
    el("host-admin-review").hidden=!review;
    el("host-admin-setup").hidden=!view||view.enabled;
    el("host-admin-enabled").hidden=!view?.enabled;
    el("host-admin-lists").hidden=!view?.enabled;
    el("host-admin-empty").hidden=!!view?.pending.length;
    el("host-admin-no-grants").hidden=!!view?.administrators.length;
    el("host-admin-pending").replaceChildren(...(view?.pending||[]).map(v=>entryCard(v,true)));
    el("host-admin-grants").replaceChildren(...(view?.administrators||[]).map(v=>entryCard(v,false)));
    el<HTMLButtonElement>("host-admin-enable").disabled=busy||!!pending||!view;
    el<HTMLButtonElement>("host-admin-refresh").disabled=busy;
    if(review) {
      el("host-admin-review-title").textContent=adminActionNames[review.reference.action];
      const list=el("host-admin-review-lines");list.replaceChildren();
      const lines:[string,string][]=[["Network",review.network]];
      if(review.device)lines.push(["Requesting device",review.device.device_name],["Device fingerprint",review.device.device_fingerprint.slice(-12)],
        ["Permissions end",adminDate(review.device.access_ends)]);
      lines.push(["This review expires",adminDate(review.expires_at)]);
      for(const [label,value] of lines)list.append(node("dt",label),node("dd",value));
      el("host-admin-review-permissions").replaceChildren(...(review.device?[permissionList(review.device)]:[]));
      el("host-admin-consequence").textContent=review.consequence;
      el("host-admin-review-expired").hidden=Date.now()<Date.parse(review.expires_at);
      el("host-admin-review-digest").textContent=review.reference.review_digest;
      el<HTMLButtonElement>("host-admin-confirm").disabled=busy||!canConfirmAdmin(status,review,pending);
      el("host-admin-confirm").textContent=status?.mutation_ready?adminActionNames[review.reference.action]:"Changes unavailable in this build";
    }
    el("host-admin-outcome").hidden=!outcome&&!pending;
    el("host-admin-outcome-title").textContent=outcome ? outcome.kind==="confirmed"?"State confirmed":outcome.kind==="refused"?(outcome.observed?"Current state checked":"Change refused"):"Check this change" : "Check the earlier change";
    const foreignOutcome=!!outcome && !!view && outcome.reference.scope!==view.scope;
    el("host-admin-outcome-text").textContent=foreignOutcome?"An earlier change belongs to another network or host. Return to that network to check its result.":outcome?adminOutcomeText(outcome):"A saved change needs a status check. Checking does not send it again.";
    el("host-admin-outcome-detail").textContent=outcome?adminOutcomeDetail(outcome):"";
    el<HTMLButtonElement>("host-admin-check").disabled=busy||!pending;
    el("host-admin-check").hidden=!pending;
    el("host-admin-storage-note").hidden=!storageProblem;
  }
  async function load() {
    const token=presentation.token();if(!current(token)||busy)return;busy=true;problem("");render();
    try {
      const next=await invoke<AdminStatus>("host_admin_status");
      if(!current(token))return;
      const scope=next.view?.scope;
      const priorScope=status?.view?.scope||pending?.scope||review?.reference.scope;
      if(scope && priorScope && scope!==priorScope) {review=null;pending=null;if(outcome?.kind==="confirmed")outcome=null;}
      status=next;
      if(scope)syncMutation(scope);
    } catch(error) {if(current(token)){status=null;problem(hostAdminProblem(error));}}
    finally {if(current(token)){busy=false;render();}}
  }
  async function prepare(action:AdminAction,enrollment_id:string|null=null) {
    const token=presentation.token();if(!current(token)||busy||pending)return;busy=true;problem("");outcome=null;render();
    try {const next=await invoke<AdminReview>("host_admin_review",{query:{action,enrollment_id}});if(current(token))review=next;}
    catch {if(current(token))problem("This request changed, expired, or could not be checked. Refresh the current requests before reviewing again. No change was sent.");}
    finally {if(current(token)){busy=false;render();if(review){dialog.scrollTop=0;const heading=el("host-admin-review-title");heading.tabIndex=-1;heading.focus({preventScroll:true});}}}
  }
  async function commit() {
    const token=presentation.token();if(!current(token)||busy||!canConfirmAdmin(status,review,pending)||!review)return;
    const reference=review.reference;
    mutations.begin(reference);pending=reference;saveReference(reference.scope,reference);busy=true;problem("");render();
    try {
      const value=await invoke<AdminOutcome>("host_admin_commit",{reference});settleMutation(reference,value);
    } catch {settleMutation(reference,{reference,kind:"uncertain",observed:null,detail:"The reply was not received. Check status; the change will not be sent again automatically."});}
    finally {if(current(token)){review=null;busy=false;syncMutation(reference.scope);render();}}
    if(current(token))await load();
  }
  async function check() {
    const token=presentation.token();if(!current(token)||busy||!pending)return;
    const reference=pending, revision=mutations.restore(reference).revision;busy=true;problem("");render();
    try {
      const value=await invoke<AdminOutcome>("host_admin_check",{reference});if(current(token))settleMutation(reference,value,revision);
    } catch {if(current(token))problem("Couldn’t confirm the saved change in this network. Keep the original network open and check status again. No change was resent.");}
    finally {if(current(token)){busy=false;render();}}
    if(current(token))await load();
  }
  el("host-admin-open").addEventListener("click",open);
  el("host-admin-close").addEventListener("click",close);
  dialog.addEventListener("cancel",invalidatePresentation);
  dialog.addEventListener("close",()=>{if(!dialog.open)invalidatePresentation();});
  el("host-admin-refresh").addEventListener("click",restart);
  el("host-admin-back").addEventListener("click",restart);
  el("host-admin-enable").addEventListener("click",()=>void prepare("enable"));
  el("host-admin-confirm").addEventListener("click",()=>void commit());
  el("host-admin-check").addEventListener("click",()=>void check());
  setInterval(()=>{if(dialog.open&&review){
    el("host-admin-review-expired").hidden=Date.now()<Date.parse(review.expires_at);
    el<HTMLButtonElement>("host-admin-confirm").disabled=busy||!canConfirmAdmin(status,review,pending);
  }},1000);
  return {close};
}
