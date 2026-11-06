import type {PairingPermission} from "./host-admin-state";
export type EnrollmentStatus="reviewed"|"uncertain"|"pending"|"active"|"declined"|"expired"|"revoked"|"missing";
export interface EnrollmentEntry {
  request_id:string;status:EnrollmentStatus;last_observed:EnrollmentStatus|null;observed_at:string|null;
  permissions:PairingPermission[];request_ends:string;access_ends:string;
}
export interface EnrollmentOverview {
  context:string;network:string;host:string;availability:"member"|"network_computer"|"unjoined"|"disconnected"|"unavailable";
  attention:boolean;can_check:boolean;entry:EnrollmentEntry|null;
}
export function enrollmentCopy(value:EnrollmentOverview):{title:string;body:string;next:string} {
  switch(value.availability) {
    case "disconnected":return {title:"Reconnect to check permissions",body:"This device is disconnected. Its saved request has not been replaced.",next:"Close this screen and choose Reconnect in Settings, then return here."};
    case "unjoined":return {title:"Join your network first",body:"This device needs to join before it can have joining permissions.",next:"Close this screen and use Join a network to connect this device."};
    case "network_computer":return {title:"Review requests on this computer",body:"This computer runs your network and reviews administrator requests.",next:"Close this screen and choose Manage administrators in Devices."};
    case "unavailable":return {title:"Connect to your network computer",body:"This device needs its saved network-computer connection to check administration requests.",next:"Keep the existing network and device identity. Review the connection in Settings."};
  }
  if(value.attention)return {title:"Your saved request needs attention",body:"It could not be safely read. The app has not replaced it or created another identity.",next:"Unlock this device and choose Refresh. If this continues, keep your network saved and use Help in Settings."};
  if(!value.entry)return {title:"No joining permissions requested",body:`The owner of ${value.host} must approve each device that helps manage who joins.`,next:"Requesting administration is not available in this version. An existing saved request can be checked here."};
  switch(value.entry.status) {
    case "reviewed":return {title:"Saved, not sent",body:"This request was saved for review. It has not been submitted by this device.",next:"Sending requests is not available in this version. Keep the existing network and device identity."};
    case "pending":return {title:"Waiting for approval",body:`The owner must review this exact request on ${value.host} before this device can help manage joining devices.`,next:"Choose Check status after the owner reviews it. Approval also needs supported device authentication."};
    case "active":return {title:"Approved at last check",body:"The network computer confirmed the permissions shown below at the last check.",next:"Joining controls are not available in this version. Every future use must check current membership and permissions again."};
    case "declined":return {title:"Request declined",body:"The owner declined this request. It did not grant administration permissions.",next:"Declining this request does not remove the device's network membership. Replacement requests are not available in this version."};
    case "expired":return {title:"Request or permissions expired",body:"The network computer reported that this request or its permissions expired.",next:"A previous approval does not extend its expiry. Replacement requests are not available in this version."};
    case "revoked":return {title:"Joining permissions revoked",body:"The owner ended the administration permissions for this request.",next:"These permissions are separate from network membership and access to files or services."};
    case "missing":return {title:"Request not found on the network computer",body:"The network computer could not find this saved request. It may not have received it or may no longer retain it.",next:"Keep the saved request and contact the owner. Checking will not resend or replace it."};
    default:return {title:"Check your saved request",body:"The latest result is unconfirmed. Your original request stays saved on this device.",next:`Choose Check status when this device and ${value.host} are online. Checking will not send another request.`};
  }
}
export function markEnrollmentUncertain(value:EnrollmentOverview):EnrollmentOverview {
  return value.entry&&value.entry.status!=="reviewed"?{...value,entry:{...value.entry,status:"uncertain"}}:value;
}
export function enrollmentObservation(value:EnrollmentEntry):string {
  const names:Record<EnrollmentStatus,string>={reviewed:"saved for review",uncertain:"unconfirmed",pending:"waiting for approval",active:"approved",declined:"declined",expired:"expired",revoked:"revoked",missing:"not found"};
  return value.last_observed?`Previously observed: ${names[value.last_observed]}. This is history, not a new permission check.`:"No earlier host result has been confirmed.";
}
export function canCheckEnrollment(value:EnrollmentOverview|null):boolean {
  return value?.availability==="member"&&!value.attention&&!!value.can_check&&!!value.entry&&value.entry.status!=="reviewed";
}
export function matchesEnrollmentReadback(expected:EnrollmentOverview,next:EnrollmentOverview):boolean {
  return next.availability==="member"&&next.context===expected.context&&!!expected.entry&&next.entry?.request_id===expected.entry.request_id;
}
export function enrollmentProblem(error:unknown):string {
  return /busy|connection is changing/i.test(String(error))?"This device is handling another change. Wait a moment, then refresh or check status.":"Couldn’t confirm the saved request. Unlock this device and keep Connect open on your network computer, then check again. Your saved request was not resent or replaced.";
}
