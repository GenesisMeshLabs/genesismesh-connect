import { invoke } from "@tauri-apps/api/core";
import { el } from "./ui";
import { friendlyProblem, isService, type HomeSpace, type HomeStatus } from "./home-state";
import { accessOutcomeText, accessReviewLines, type AccessOutcome } from "./access-state";
import { icon } from "./icons";
import { activityGroups, activityRowDetail, activityLabel, activityExplanation, recoveryExplanation, exportRecordMessage, summaryAfterCheck, type ActivitySummary, type HistoryCursor, type HistoryPage, type LocalAccessRecord } from "./activity-state";

export function setupActivity(getStatus:()=>HomeStatus|null,isActive:()=>boolean,refreshHome:()=>Promise<void>,message:(s:string)=>void,manage:(space:HomeSpace)=>Promise<void>) {
  const detail=el<HTMLDialogElement>("activity-detail");
  let filter:"all"|"needs_attention"="all",entries:ActivitySummary[]=[],next:HistoryCursor|null=null;
  let scope:string|null=null,stamp="",epoch=0,loading=false,working=false,loaded=false,failed=false;
  let selected:ActivitySummary|null=null,local:LocalAccessRecord|null=null;
  function problem(value:string){failed=!!value;el("activity-problem").textContent=value;el("activity-problem").hidden=!value;}
  function detailProblem(value:string){el("activity-detail-problem").textContent=value;el("activity-detail-problem").hidden=!value;}
  function reset(){epoch++;loading=false;loaded=false;entries=[];next=null;selected=null;local=null;detail.close();el("activity-list-main").replaceChildren();el("activity-more").hidden=true;el("activity-incomplete").hidden=true;attention(0);problem("");render();}
  function attention(count:number){el("activity-attention-chip").textContent=count?`Needs attention · ${count}`:"Needs attention";}
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
  // A row opens its record; checking a result happens there, never from the list.
  function row(entry:ActivitySummary,now:Date){
    const item=document.createElement("li");item.className="list-row";
    const main=document.createElement("button");main.className="row-main";
    const marker=document.createElement("span");marker.className=entry.needs_attention?"row-tile attention":"row-tile";
    marker.append(icon(entry.needs_attention?"circle-alert":"circle-check"));
    const words=document.createElement("span");words.className="row-text";
    const name=document.createElement("strong");name.textContent=entry.name;
    const detail=document.createElement("span");detail.textContent=activityRowDetail(entry,now);
    if(entry.needs_attention)detail.className="row-warning";
    words.append(name,detail);main.append(marker,words);
    main.addEventListener("click",()=>void showDetail(entry,main));
    item.append(main,icon("chevron-right",20));
    return item;
  }
  function render(){
    const list=el("activity-list-main");list.replaceChildren();
    el("activity-empty").hidden=entries.length>0||loading||!loaded||failed;
    el("activity-empty-title").textContent=filter==="needs_attention"?"No matching changes need attention":"No access changes yet";
    el("activity-empty-text").textContent=filter==="needs_attention"?"This view shows unconfirmed or conflicting access changes saved on this device.":"When you review or change access to a shared item, Connect keeps a local record here.";
    const now=new Date();
    for(const group of activityGroups(entries,now)){
      const label=document.createElement("h2");label.className="section-label";label.textContent=group.day;
      const rows=document.createElement("ol");rows.className="list-group";
      for(const entry of group.entries)rows.append(row(entry,now));
      list.append(label,rows);
    }
    el<HTMLButtonElement>("activity-refresh").disabled=loading;
    el("activity-refresh").setAttribute("aria-busy",String(loading));
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
      attention(page.attention_count);
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
