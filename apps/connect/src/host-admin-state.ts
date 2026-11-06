export type AdminAction = "enable" | "approve" | "decline" | "revoke";
export type AdminDecision = "pending" | "approved" | "declined" | "revoked" | "expired";
export type PairingPermission = "list_pairing" | "approve_pairing" | "reject_pairing";
export interface AdminEntry {
  id: string; device_name: string; device_fingerprint: string; known_device: boolean;
  permissions: PairingPermission[]; access_ends: string; request_ends: string;
  decision: AdminDecision; enrollment_digest: string;
}
export interface AdminReference {
  review_id: string; review_digest: string; scope: string; action: AdminAction;
  enrollment_id: string | null; enrollment_digest: string | null;
}
export interface AdminReview {
  reference: AdminReference; network: string; device: AdminEntry | null;
  expires_at: string; consequence: string;
}
export interface AdminView { scope: string; network: string; enabled: boolean; pending: AdminEntry[]; administrators: AdminEntry[] }
export interface AdminStatus {
  location: "host" | "member" | "unsupported";
  mutation_ready: boolean; readiness: string; view: AdminView | null;
}
export interface AdminOutcome {
  reference: AdminReference; kind: "confirmed" | "refused" | "uncertain";
  observed: AdminDecision | null; detail: string;
}
const permissionNames: Record<PairingPermission,string> = {
  list_pairing: "See requests to join your network",
  approve_pairing: "Approve new devices joining your network",
  reject_pairing: "Decline requests to join your network",
};
export const adminActionNames: Record<AdminAction,string> = {
  enable: "Enable administrator requests", approve: "Approve pairing permissions",
  decline: "Decline this request", revoke: "Revoke pairing permissions",
};
export function permissionName(permission: PairingPermission): string {return permissionNames[permission] || "Unsupported permission";}
export function adminDate(value:string) {
  const date=new Date(value);
  return Number.isFinite(date.getTime()) ? date.toLocaleString(undefined,{year:"numeric",month:"short",day:"numeric",hour:"numeric",minute:"2-digit",second:"2-digit",timeZoneName:"short"}) : "Expiry unavailable";
}
export function canConfirmAdmin(status:AdminStatus|null, review:AdminReview|null, pending:AdminReference|null, now=Date.now()):boolean {
  return status?.location==="host" && !!status.mutation_ready && !!status.view && !!review && !pending
    && Object.prototype.hasOwnProperty.call(adminActionNames,review.reference.action)
    && status.view.scope===review.reference.scope && Number.isFinite(Date.parse(review.expires_at)) && now<Date.parse(review.expires_at)
    && (!review.device || review.device.permissions.length>0 && review.device.permissions.every(p=>Object.prototype.hasOwnProperty.call(permissionNames,p)))
    && (review.reference.action!=="approve" || !!review.device?.known_device);
}
export function adminOutcomeText(value:AdminOutcome):string {
  if(value.kind==="uncertain")return "This change is unconfirmed. Check status before making another change. It will not be sent again automatically.";
  if(value.observed==="revoked")return "These pairing permissions are revoked. The device stays a network member.";
  if(value.observed==="expired")return "This request or its pairing permissions have expired. Refresh to review the current state.";
  if(value.observed==="declined")return "This request was declined. The device received no administrator permissions from it.";
  if(value.kind==="refused"&&value.observed==="approved")return "This device currently has approved pairing permissions. Review revocation if you want to end them.";
  if(value.kind==="refused")return "This change was not confirmed. Review the reason and the current administrator state below.";
  if(value.reference.action==="enable")return "Administrator requests are enabled on this computer.";
  if(value.observed==="approved")return "The device has the reviewed pairing permissions until its expiry.";
  return "The current administrator state has been checked.";
}
export function adminOutcomeDetail(value:AdminOutcome):string {
  if(value.kind!=="refused"||value.observed)return value.detail;
  if(/authentication.*unavailable|authentication.*not available/i.test(value.detail))return "Administrator changes need supported device authentication, which this build does not provide yet.";
  if(/authentication.*canceled|authentication.*cancelled/i.test(value.detail))return "Device authentication was canceled. No change was sent.";
  if(/expired|validity/i.test(value.detail))return "The review or permission expired. Refresh to review the current request.";
  if(/changed|different network|another network|another host/i.test(value.detail))return "The device, request or network changed after review. Refresh before reviewing it again.";
  if(/certificate|membership|member context/i.test(value.detail))return "The device’s current network membership could not be confirmed. Refresh Devices before reviewing its permissions.";
  return "Your network computer refused this review. Refresh to check its current administrator state.";
}
export function hostAdminProblem(detail:unknown):string {
  if(/busy|handling another request|in progress|connection.*changing/i.test(String(detail)))return "Your network computer is handling another change. Wait a moment, then refresh or check status.";
  if(/managed Connect authority|incompatible|update.*network computer|version is incompatible/i.test(String(detail)))return "This network host cannot manage these requests yet. Use a supported, up-to-date Connect authority.";
  return "Couldn’t check this computer’s administrator setup. Keep Connect open on the network computer and choose Refresh. No change was sent.";
}
/** Local persistence is only a readback bookmark. Native code checks scope and
 * the original enrollment; this object cannot authorize or replay a change. */
export function parseAdminReference(raw:string|null):AdminReference|null {
  if(!raw || raw.length>2048)return null;
  try {
    const value:unknown=JSON.parse(raw);
    if(!value || typeof value!=="object" || Array.isArray(value))return null;
    const r=value as Record<string,unknown>;
    const keys=["review_id","review_digest","scope","action","enrollment_id","enrollment_digest"];
    if(Object.keys(r).length!==keys.length || Object.keys(r).some(k=>!keys.includes(k)))return null;
    const bounded=(v:unknown)=>typeof v==="string" && v.length>0 && v.length<=128;
    const uuid=(v:unknown)=>typeof v==="string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
    if(!uuid(r.review_id)||!bounded(r.review_digest)||!bounded(r.scope)||typeof r.action!=="string"||!Object.prototype.hasOwnProperty.call(adminActionNames,r.action))return null;
    if(r.action==="enable" ? r.enrollment_id!==null||r.enrollment_digest!==null : !uuid(r.enrollment_id)||!bounded(r.enrollment_digest))return null;
    return r as unknown as AdminReference;
  } catch {return null;}
}
