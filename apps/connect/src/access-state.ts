import { formatBytes } from "./home-state.ts";

export interface AccessPolicy {
  version:number; recipients:string[]; expires_at:string|null;
  max_bytes:number; max_seconds:number; extra_gates:unknown[];
}
export interface AccessRecord {
  intent: {
    id:string; collection:string; name:string;
    context:{pin:{network_name:string;root_public_key:string};actor:string;audience:string};
    before:AccessPolicy; after:AccessPolicy; created_at:string; expires_at:string;
  };
  digest:string;
  stage:"prepared"|"submitted"|"unknown"|"state_observed"|"conflict"|"cancelled";
  authorization:"not_evaluated"|"core_accepted"|"unknown";
  observed:AccessPolicy|null;
  updated_at:string;
}
export interface AccessOutcome { record:AccessRecord; local_applied:boolean; problem:string|null }
export interface ResourceCapabilities {
  profile:"connect_managed"|"connect_restricted"|"external_unverified";
  operations:string[];
}
export function accessPrerequisiteText(capabilities:ResourceCapabilities):string {
  if(capabilities.profile==="external_unverified")return "You can view access here. Changes are read-only until your network computer can verify the external authority’s version and settings.";
  if(capabilities.profile!=="connect_managed")return "You can view access here. On your network computer, check that policy enforcement is required and its operator can manage policies.";
  if(!capabilities.operations.includes("connect.access.update.v1"))return "Your network computer has not enabled access changes for this item. Review its setup there.";
  return "";
}
export function needsAccessCheck(outcome:AccessOutcome|null):boolean {
  return !!outcome && (outcome.record.stage==="unknown" || outcome.record.stage==="submitted" || (outcome.record.stage==="state_observed" && !outcome.local_applied));
}
export function accessOutcomeText(outcome:AccessOutcome):string {
  if(outcome.record.stage==="conflict") return "Access now differs from your review. Reload the current settings before making another change.";
  if(outcome.record.stage==="state_observed") {
    if(!outcome.local_applied) return "Your network has the reviewed settings. This device still needs to refresh its shared item. Choose Check status.";
    return outcome.record.authorization==="core_accepted" ? "Access saved and checked." : "Your network now has the reviewed settings. This check cannot tell which request applied them.";
  }
  return "Your change may have reached the network computer, but its result is unconfirmed. Choose Check status. Connect will not send it again automatically.";
}
export type AccessEnds = "ongoing" | "hour" | "tonight" | "week" | "date";
/** When access ends for one of the quick choices; null for ongoing or a chosen date. */
export function accessEndsAt(choice:AccessEnds, now:Date):Date|null {
  if(choice==="hour") return new Date(now.getTime()+3600_000);
  if(choice==="week") return new Date(now.getTime()+7*24*3600_000);
  if(choice==="tonight") { const end=new Date(now); end.setHours(23,59,0,0); if(end<=now) end.setDate(end.getDate()+1); return end; }
  return null;
}
function minutes(seconds:number):string {
  return seconds%3600===0 ? `${seconds/3600} hour${seconds===3600?"":"s"}` : `${Math.round(seconds/60)} minutes`;
}
export function accessReviewLines(record:AccessRecord, devices:{id:string;name:string}[], service:boolean):[string,string][] {
  const {intent}=record, after=intent.after;
  const label=(id:string)=>{
    const name=devices.find(d=>d.id===id)?.name;
    return name ? (devices.filter(d=>d.name===name).length>1 ? `${name} (${id.slice(0,8)}…)` : name) : `Device ${id.slice(0,8)}…`;
  };
  const removed=intent.before.recipients.filter(id=>!after.recipients.includes(id));
  const added=after.recipients.filter(id=>!intent.before.recipients.includes(id));
  const lines:[string,string][]=[
    ["Network",intent.context.pin.network_name], ["Shared item",intent.name],
    ["Allowed devices",after.recipients.map(label).join(", ")],
    ["Devices gaining access",added.length ? added.map(label).join(", ") : "None"],
    ["Devices losing access",removed.length ? removed.map(label).join(", ") : "None"],
    ["Access ends",after.expires_at ? new Date(after.expires_at).toLocaleString(undefined,{weekday:"short",day:"numeric",month:"short",hour:"numeric",minute:"2-digit"}) : "When you stop sharing"],
    ["Largest file or connection",after.max_bytes===9007199254740991 ? "No limit" : formatBytes(after.max_bytes)],
  ];
  if(service) lines.push(["Each visit can last",minutes(after.max_seconds)]);
  const changed=JSON.stringify(after.extra_gates)!==JSON.stringify(intent.before.extra_gates);
  if(after.extra_gates.length||changed) lines.push(["Expert rules",`${after.extra_gates.length} · ${changed ? "changed; your network checks them when you confirm" : "unchanged"}`]);
  return lines;
}
