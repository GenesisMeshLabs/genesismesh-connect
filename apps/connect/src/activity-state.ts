import type { AccessRecord, AccessOutcome } from "./access-state.ts";
export type RecoveryHint="check_status"|"disconnected"|"previous_host"|"item_stopped"|"archived"|"settled";
export interface ActivitySummary {
  id:string;collection:string;name:string;created_at:string;updated_at:string;
  stage:AccessRecord["stage"];authorization:AccessRecord["authorization"];
  policy_before:number;policy_observed:number|null;recipients_before:number;recipients_after:number;
  archived:boolean;needs_attention:boolean;recovery:RecoveryHint;
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
  return "Result unconfirmed";
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
export function activityCount(count:number,incomplete:boolean):string {
  return count ? `${count} ${incomplete?"shown ":""}${count===1?"change needs":"changes need"} attention` : incomplete ? "Some older history is unavailable" : "No access changes need attention";
}
export function exportRecordMessage(status:"saved"|"cancelled"|"share_sheet_opened"):string {
  return status==="saved"?"Local record saved. It contains unsigned workflow history, not a signed audit report.":status==="share_sheet_opened"?"Choose where to save or share the local record.":"Saving cancelled.";
}
