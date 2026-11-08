import type { AccessRecord, AccessOutcome } from "./access-state.ts";
export type RecoveryHint="check_status"|"disconnected"|"previous_host"|"item_stopped"|"archived"|"settled";
export interface ActivitySummary {
  id:string;collection:string;name:string;created_at:string;updated_at:string;
  stage:AccessRecord["stage"];authorization:AccessRecord["authorization"];
  policy_before:number;policy_observed:number|null;recipients_before:number;recipients_after:number;
  archived:boolean;needs_attention:boolean;recovery:RecoveryHint;
}
const dayStart=(d:Date)=>new Date(d.getFullYear(),d.getMonth(),d.getDate()).getTime();
const daysBefore=(at:Date,now:Date)=>Math.round((dayStart(now)-dayStart(at))/86400000);
const clock=(at:Date)=>at.toLocaleTimeString(undefined,{hour:"numeric",minute:"2-digit"});
/** "Today, 14:05", "Yesterday, 09:30" or "5 Nov, 18:20", in this device's time zone. */
export function whenText(iso:string, now=new Date()):string {
  const at=new Date(iso), days=daysBefore(at,now);
  if(days===0)return `Today, ${clock(at)}`;
  if(days===1)return `Yesterday, ${clock(at)}`;
  const date=at.toLocaleDateString(undefined,{day:"numeric",month:"short",...(at.getFullYear()===now.getFullYear()?{}:{year:"numeric"})});
  return `${date}, ${clock(at)}`;
}
export type ActivityDay="Today"|"Yesterday"|"Earlier";
/** A record from a clock ahead of this one still counts as today. */
export function activityDay(iso:string, now=new Date()):ActivityDay {
  const days=daysBefore(new Date(iso),now);
  return days<=0?"Today":days===1?"Yesterday":"Earlier";
}
/** Today, Yesterday and Earlier, each keeping the order it was given; empty days are left out. */
export function activityGroups<T extends {created_at:string}>(entries:T[], now=new Date()):{day:ActivityDay;entries:T[]}[] {
  const days:ActivityDay[]=["Today","Yesterday","Earlier"];
  const groups=days.map(day=>({day,entries:[] as T[]}));
  for(const entry of entries)groups[days.indexOf(activityDay(entry.created_at,now))].entries.push(entry);
  return groups.filter(group=>group.entries.length>0);
}
/** One line under the item's name: what happened, then when. The day heading already says which day. */
export function activityRowDetail(entry:Pick<ActivitySummary,"stage"|"authorization"|"created_at">, now=new Date()):string {
  const at=new Date(entry.created_at);
  return `${activityLabel(entry)} · ${activityDay(entry.created_at,now)==="Earlier"?whenText(entry.created_at,now):clock(at)}`;
}
export interface HistoryCursor {scope_id:string;filter:"all"|"needs_attention";before_created_at:string;before_id:string}
export interface HistoryPage {scope_id:string;entries:ActivitySummary[];next:HistoryCursor|null;attention_count:number;incomplete:boolean}
export interface LocalAccessRecord {format:string;evidence_class:string;signed:false;archived:boolean;record:AccessRecord}
export function summaryAfterCheck(entry:ActivitySummary,outcome:AccessOutcome):ActivitySummary {
  const needs_attention=["unknown","submitted","conflict"].includes(outcome.record.stage);
  return {...entry,stage:outcome.record.stage,authorization:outcome.record.authorization,updated_at:outcome.record.updated_at,
    policy_observed:outcome.record.observed?.version??null,needs_attention,recovery:needs_attention?entry.recovery:"settled"};
}
export function activityLabel(entry:Pick<ActivitySummary,"stage"|"authorization">):string {
  if(entry.stage==="prepared")return "Not sent";
  if(entry.stage==="cancelled")return "Cancelled before sending";
  if(entry.stage==="state_observed")return entry.authorization==="core_accepted"?"Access update checked":"Matching settings observed";
  if(entry.stage==="conflict")return "Settings changed";
  return "Not confirmed yet";
}
export function activityExplanation(entry:Pick<ActivitySummary,"stage"|"authorization">):string {
  if(entry.stage==="prepared")return "A review was saved on this device. Nothing was sent from that review.";
  if(entry.stage==="cancelled")return "The review was cancelled before its change was sent.";
  if(entry.stage==="state_observed")return entry.authorization==="core_accepted"?
    "Your network accepted this change, and the reviewed settings were observed. This does not show whether a file or service was used.":
    "Settings matched the review, but the original response was missing. This check cannot identify which request applied them.";
  if(entry.stage==="conflict")return "The settings differed from this review when checked. Review the latest settings before making another change.";
  return "The change may have reached your network computer. Check its status; Connect will not send it again automatically.";
}
export function recoveryExplanation(hint:RecoveryHint):string {
  return {
    check_status:"Check the current result without sending the change again.",
    disconnected:"Reconnect in Settings to check the current result. Your saved history remains available here.",
    previous_host:"This record names a previous network computer. Review the earlier result on that computer.",
    item_stopped:"This item is no longer shared here. Review the earlier result on your network computer.",
    archived:"This is an older saved record. It cannot approve or resend a change.",
    settled:"Saved history. No action is sent from this record.",
  }[hint];
}
export function exportRecordMessage(status:"saved"|"cancelled"|"share_sheet_opened"):string {
  return status==="saved"?"Local record saved. It contains unsigned workflow history, not a signed audit report.":status==="share_sheet_opened"?"Choose where to save or share the local record.":"Saving cancelled.";
}
