import { invoke } from "@tauri-apps/api/core";
import { el } from "./ui";
import { friendlyProblem, isService, type HomeSpace, type HomeStatus } from "./home-state";
import { accessOutcomeText, accessReviewLines, type AccessOutcome } from "./access-state";
import { activityLabel, activityExplanation, activityCount, recoveryExplanation, exportRecordMessage, summaryAfterCheck, type ActivitySummary, type HistoryCursor, type HistoryPage, type LocalAccessRecord } from "./activity-state";

export function setupActivity(getStatus:()=>HomeStatus|null,isActive:()=>boolean,refreshHome:()=>Promise<void>,message:(s:string)=>void,manage:(space:HomeSpace)=>Promise<void>) {
  const detail=el<HTMLDialogElement>("activity-detail");
  let filter:"all"|"needs_attention"="all",entries:ActivitySummary[]=[],next:HistoryCursor|null=null;
  let scope:string|null=null,stamp="",epoch=0,loading=false,working=false,loaded=false,failed=false;
  let selected:ActivitySummary|null=null,local:LocalAccessRecord|null=null;
  function problem(value:string){failed=!!value;el("activity-problem").textContent=value;el("activity-problem").hidden=!value;}
  function detailProblem(value:string){el("activity-detail-problem").textContent=value;el("activity-detail-problem").hidden=!value;}
  function reset(){epoch++;loading=false;loaded=false;entries=[];next=null;selected=null;local=null;detail.close();el("activity-list-main").replaceChildren();el("activity-more").hidden=true;el("activity-incomplete").hidden=true;el("activity-review-attention").hidden=true;el("activity-attention-text").textContent="Saved access history on this device";problem("");render();}
  function button(label:string,action:(button:HTMLButtonElement)=>Promise<void>){
    const b=document.createElement("button");b.className="secondary";b.textContent=label;
    b.addEventListener("click",()=>void action(b));return b;
  }
  function canCheck(entry:ActivitySummary){return entry.recovery==="check_status"&&!getStatus()?.disconnected;}
  async function checked(entry:ActivitySummary,b:HTMLButtonElement){
    if(working)return;working=true;b.disabled=true;detailProblem("");problem("");
    const originalScope=scope;
    try{
      const outcome=await invoke<AccessOutcome>("check_activity_record",{request:{id:entry.id}});
      if(scope!==originalScope)return;
      message(accessOutcomeText(outcome));
      if(local?.record.intent.id===entry.id)local={...local,record:outcome.record};
      await load(false);
      if(selected?.id===entry.id)selected=entries.find(item=>item.id===entry.id)||summaryAfterCheck(entry,outcome);
      if(detail.open&&selected&&local)renderDetail();
      await refreshHome();
    }catch(e){if(scope===originalScope){const text=friendlyProblem(String(e));problem(text);detailProblem(text);}}
    finally{working=false;b.disabled=false;}
  }
  async function showDetail(entry:ActivitySummary,b:HTMLButtonElement){
    if(working)return;working=true;b.disabled=true;const originalScope=scope;
    try{
      const record=await invoke<LocalAccessRecord>("get_activity_record",{request:{id:entry.id}});
      if(scope!==originalScope)return;
      selected=entry;local=record;detailProblem("");renderDetail();detail.showModal();
    }catch(e){if(scope===originalScope)problem(friendlyProblem(String(e)));}
    finally{working=false;b.disabled=false;}
  }
  function renderDetail(){
    if(!local||!selected)return;
    el("activity-detail-message").textContent="";
    el("activity-detail-title").textContent=local.record.intent.name;
    el("activity-detail-status").textContent=activityLabel(local.record);
    el("activity-detail-explanation").textContent=activityExplanation(local.record);
    el("activity-detail-recovery").textContent=recoveryExplanation(selected.recovery);
    const fields=el("activity-detail-fields");fields.replaceChildren();
    const space=getStatus()?.spaces.find(s=>s.id===selected?.collection&&s.own);
    const lines=accessReviewLines(local.record,getStatus()?.devices||[],!!space&&isService(space));
    lines.push(["Observed policy version",selected.policy_observed===null?"No readback recorded":String(selected.policy_observed)]);
    lines.push(["Saved source",local.archived?"Older archive on this device":"Current journal on this device"]);
    for(const [label,value] of lines){const term=document.createElement("dt"),description=document.createElement("dd");term.textContent=label;description.textContent=value;fields.append(term,description);}
    el("activity-detail-exact").textContent=JSON.stringify(local,null,2);
    el<HTMLButtonElement>("activity-detail-check").hidden=!canCheck(selected);
    el<HTMLButtonElement>("activity-detail-manage").hidden=!space||!!getStatus()?.disconnected;
  }
  function render(){
    const list=el("activity-list-main");list.replaceChildren();
    el("activity-empty").hidden=entries.length>0||loading||!loaded||failed;
    el("activity-empty-title").textContent=filter==="needs_attention"?"No matching changes need attention":"Your access changes will appear here";
    el("activity-empty-text").textContent=filter==="needs_attention"?"This view shows unconfirmed or conflicting access changes saved on this device.":"When you review or change access to a shared item, Connect keeps a local record here.";
    for(const entry of entries){
      const card=document.createElement("li");card.className="home-card activity-entry";
      const heading=document.createElement("div");heading.className="activity-entry-heading";
      const title=document.createElement("h2");title.textContent=entry.name;
      const badge=document.createElement("span");badge.className=entry.needs_attention?"activity-status attention":"activity-status";badge.textContent=activityLabel(entry);heading.append(title,badge);
      const when=document.createElement("p");when.className="home-muted";when.textContent=`${new Date(entry.created_at).toLocaleString()}${entry.archived?" · Older saved record":""}`;
      const description=document.createElement("p");description.textContent=activityExplanation(entry);
      const scope=document.createElement("p");scope.className="home-muted";scope.textContent=`Allowed devices: ${entry.recipients_before} → ${entry.recipients_after} · Policy ${entry.policy_before}${entry.policy_observed===null?"":` → observed ${entry.policy_observed}`}`;
      const actions=document.createElement("div");actions.className="button-row";
      if(canCheck(entry))actions.append(button("Check status",b=>checked(entry,b)));
      else if(entry.needs_attention){const hint=document.createElement("p");hint.className="home-muted";hint.textContent=recoveryExplanation(entry.recovery);card.append(hint);}
      actions.append(button("View record",b=>showDetail(entry,b)));
      card.prepend(heading,when,description,scope);card.append(actions);list.append(card);
    }
    el<HTMLButtonElement>("activity-refresh").disabled=loading;
    el("activity-refresh").textContent=loading?"Loading…":"Refresh";
    el<HTMLButtonElement>("activity-more").disabled=loading;
    el("activity-more").hidden=!next;
    el("activity-loading").hidden=!loading;
    for(const b of document.querySelectorAll<HTMLElement>("[data-activity-filter]"))b.setAttribute("aria-pressed",String(b.dataset.activityFilter===filter));
  }
  async function load(append:boolean){
    if(loading||!scope)return;
    const token=++epoch,expectedScope=scope;loading=true;problem("");render();
    try{
      const page=await invoke<HistoryPage>("get_access_activity",{request:{filter,limit:20,cursor:append?next:null}});
      if(token!==epoch||scope!==expectedScope)return;
      if(page.scope_id!==expectedScope){reset();problem("Your network changed. Refresh Activity to show its saved history.");await refreshHome();return;}
      const seen=new Set(append?entries.map(e=>e.id):[]);
      const fresh=page.entries.filter(entry=>{if(seen.has(entry.id))return false;seen.add(entry.id);return true;});
      entries=append?[...entries,...fresh]:fresh;next=page.next;loaded=true;
      el("activity-attention-text").textContent=activityCount(page.attention_count,page.incomplete);
      el("activity-review-attention").hidden=page.attention_count===0||filter==="needs_attention";
      el("activity-incomplete").hidden=!page.incomplete;
    }catch(e){if(token===epoch)problem(friendlyProblem(String(e)));}
    finally{if(token===epoch){loading=false;render();}}
  }
  function changed(status:HomeStatus){
    const nextScope=status.configured?(status.activity_scope||null):null;
    const nextStamp=JSON.stringify([nextScope,status.disconnected,status.owner,status.devices.find(d=>d.authority_connection)?.id,status.spaces.filter(s=>s.own).map(s=>s.id).sort()]);
    if(scope!==nextScope){reset();scope=nextScope;}
    if(stamp!==nextStamp){stamp=nextStamp;if(isActive()&&scope)void load(false);}
  }
  el("activity-refresh").addEventListener("click",()=>void load(false));
  el("activity-more").addEventListener("click",()=>{if(next)void load(true);});
  function choose(value:"all"|"needs_attention"){if(loading)return;filter=value;entries=[];next=null;void load(false);}
  for(const b of document.querySelectorAll<HTMLElement>("[data-activity-filter]"))b.addEventListener("click",()=>choose(b.dataset.activityFilter==="needs_attention"?"needs_attention":"all"));
  el("activity-review-attention").addEventListener("click",()=>choose("needs_attention"));
  el("activity-detail-close").addEventListener("click",()=>{if(!working)detail.close();});
  detail.addEventListener("cancel",e=>{if(working)e.preventDefault();});
  el<HTMLButtonElement>("activity-detail-check").addEventListener("click",e=>{if(selected&&canCheck(selected))void checked(selected,e.currentTarget as HTMLButtonElement);});
  el("activity-detail-manage").addEventListener("click",async()=>{
    const space=getStatus()?.spaces.find(s=>s.id===selected?.collection&&s.own);if(!space||working)return;
    detail.close();try{await manage(space);}catch(e){problem(friendlyProblem(String(e)));}
  });
  el<HTMLButtonElement>("activity-detail-save").addEventListener("click",async e=>{
    if(!selected||working)return;working=true;const b=e.currentTarget as HTMLButtonElement;b.disabled=true;detailProblem("");el("activity-detail-message").textContent="";const originalScope=scope;
    try{const outcome=await invoke<"saved"|"cancelled"|"share_sheet_opened">("export_activity_record",{request:{id:selected.id}});if(scope===originalScope)el("activity-detail-message").textContent=exportRecordMessage(outcome);}
    catch(e){if(scope===originalScope)detailProblem(friendlyProblem(String(e)));}finally{working=false;b.disabled=false;}
  });
  window.addEventListener("connect-access-history-changed",()=>{if(isActive())void load(false);});
  return {open:()=>load(false),changed,close:()=>detail.close()};
}
