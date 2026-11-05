import { formatBytes } from "./home-state.ts";

export interface AccessPolicy {
  version:number; recipients:string[]; expires_at:string|null;
  max_bytes:number; max_seconds:number; extra_gates:unknown[];
}
export interface AccessRecord {
  intent: {
    id:string; collection:string; name:string;
    context:{pin:{network_name:string;root_public_key:string};actor:string;audience:string};
    before:AccessPolicy; after:AccessPolicy; expires_at:string;
  };
  digest:string;
  stage:"prepared"|"submitted"|"unknown"|"state_observed"|"conflict"|"cancelled";
  authorization:"not_evaluated"|"core_accepted"|"unknown";
}
export interface AccessOutcome { record:AccessRecord; local_applied:boolean; problem:string|null }
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
export function accessReviewLines(record:AccessRecord, devices:{id:string;name:string}[], service:boolean):[string,string][] {
  const {intent}=record, after=intent.after;
  const label=(id:string)=>{
    const name=devices.find(d=>d.id===id)?.name;
    return name ? (devices.filter(d=>d.name===name).length>1 ? `${name} (${id.slice(0,8)}…)` : name) : `Device ${id.slice(0,8)}…`;
  };
  const removed=intent.before.recipients.filter(id=>!after.recipients.includes(id));
  const lines:[string,string][]=[
    ["Network",intent.context.pin.network_name], ["Shared item",intent.name],
    ["Allowed devices",after.recipients.map(label).join(", ")],
    ["Devices losing access",removed.length ? removed.map(label).join(", ") : "None"],
    ["Access ends",after.expires_at ? new Date(after.expires_at).toLocaleString(undefined,{timeZoneName:"short"}) : "Ongoing access"],
    ["Size per file or connection",after.max_bytes===9007199254740991 ? "No extra size limit" : formatBytes(after.max_bytes)],
  ];
  if(service) lines.push(["Service session limit",`${after.max_seconds} seconds`]);
  lines.push(["Additional rules",`${after.extra_gates.length} rule(s) · ${JSON.stringify(after.extra_gates)===JSON.stringify(intent.before.extra_gates) ? "unchanged" : "changed; the network validates them when saving"}`]);
  lines.push(["Review valid until",new Date(intent.expires_at).toLocaleTimeString()]);
  return lines;
}
