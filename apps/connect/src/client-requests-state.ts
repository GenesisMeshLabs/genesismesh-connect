export type RequestStatus="reviewed"|"observed"|"uncertain"|"archived";
export type PairingOperation="list_pairing"|"approve_pairing"|"reject_pairing";
export type RequestResult={state:"queue_snapshot"|"approved"|"rejected"|"in_progress"|"unconfirmed";waiting_name:string|null};
export type RequestEntry={nonce:string;digest:string;operation:PairingOperation;candidate:{name:string;comparison_code:string}|null;status:RequestStatus;current_result:RequestResult|null;last_result:RequestResult|null;observed_at:string|null;retained_result:RequestResult|null;retained_at:string|null;review_ends:string;access_ends:string};
export type RequestsOverview={context:string;network:string;host:string;availability:"member"|"unavailable"|"unjoined"|"authority_host"|"disconnected";attention:boolean;can_check:boolean;entry:RequestEntry|null};
function terminal(entry:RequestEntry,result:RequestResult|null) {
  return !!result&&({list_pairing:"queue_snapshot",approve_pairing:"approved",reject_pairing:"rejected"}[entry.operation]===result.state);
}
export function requestConfirmed(value:RequestsOverview) {
  const entry=value.entry;
  return value.availability==="member"&&!value.attention&&!!entry&&entry.status==="observed"&&!!entry.observed_at&&terminal(entry,entry.current_result)&&terminal(entry,entry.retained_result)&&entry.current_result?.waiting_name===entry.retained_result?.waiting_name;
}
export function canCheckRequest(value:RequestsOverview|null) {
  return !!value&&value.availability==="member"&&!value.attention&&value.can_check&&!!value.entry&&["uncertain","observed"].includes(value.entry.status);
}
export function matchesRequestReadback(expected:RequestsOverview,actual:RequestsOverview) {
  const a=expected.entry,b=actual.entry;
  return actual.availability==="member"&&!actual.attention&&actual.context===expected.context&&!!a&&!!b&&a.nonce===b.nonce&&a.digest===b.digest&&a.operation===b.operation&&a.candidate?.name===b.candidate?.name&&a.candidate?.comparison_code===b.candidate?.comparison_code;
}
export function requestUncertain(value:RequestsOverview):RequestsOverview {
  const entry=value.entry;if(!entry)return value;
  return {...value,entry:{...entry,status:entry.status==="reviewed"||entry.status==="archived"?entry.status:"uncertain",current_result:null,
    retained_result:entry.retained_result||(terminal(entry,entry.current_result)?entry.current_result:null),retained_at:entry.retained_at||(terminal(entry,entry.current_result)?entry.observed_at:null)}};
}
export function requestedAction(entry:RequestEntry) {
  return entry.operation==="approve_pairing"?`Approve ${entry.candidate?.name||"a joining device"}`:entry.operation==="reject_pairing"?`Decline ${entry.candidate?.name||"a joining device"}`:"Check the waiting device list";
}
export function requestHistory(entry:RequestEntry) {
  const result=entry.retained_result;if(!terminal(entry,result))return "No completed result has been recorded for this request.";
  return result!.state==="approved"?"An approval was recorded earlier. This is history, not a new confirmation of device access.":result!.state==="rejected"?"A rejection was recorded earlier. This is the earlier request's result.":"The earlier queue check was recorded. Its waiting-device list is a saved snapshot.";
}
export function requestsCopy(value:RequestsOverview):{title:string;body:string;next:string} {
  const basic={unavailable:["Device approval controls are not available yet","This device cannot send or manage device approvals from this screen.","You can view joining permissions from Devices."],unjoined:["Join your network first","Saved device requests belong to the network this device has joined.","Return to setup and join your network."],authority_host:["Manage devices on this host","This view checks requests sent from a joined device.","Use Devices to manage this host's network."],disconnected:["Reconnect to check this request","Your network connection is currently paused.","Reconnect from Settings, then check the saved request."]} as const;
  if(value.availability!=="member") {const [title,body,next]=basic[value.availability];return {title,body,next};}
  if(value.attention)return {title:"Saved request needs attention",body:"The saved request could not be verified. Keep the existing network and device identity.",next:"Unlock this device and refresh. Keep the original request while its result is unclear."};
  const entry=value.entry;
  if(!entry)return {title:"No saved device request",body:"This device has no saved approval, rejection or waiting-list check.",next:"Your joining permissions are separate. You can view them from Devices."};
  if(entry.status==="reviewed")return {title:"Saved, not sent",body:`You reviewed: ${requestedAction(entry)}. This request has not been sent.`,next:"Sending device approvals from this app is not available yet. Keep this saved request."};
  if(entry.status==="archived"&&!entry.retained_result)return {title:"Expired request closed",body:"This review expired before it was sent. It was closed on this device without contacting the network host.",next:"A new request needs its own review and approval."};
  if(entry.status==="archived")return {title:"Earlier request retained",body:"This request was closed locally after its result was checked. Its recorded result is kept below.",next:"You can close this view. A later device request has its own review."};
  if(requestConfirmed(value)) {
    const result=entry.current_result!;
    if(result.state==="approved")return {title:"Approval confirmed at last check",body:`${value.host} confirmed that this request recorded an approval for ${entry.candidate?.name||"the joining device"}.`,next:"Current device access can change. Use Devices to manage that device."};
    if(result.state==="rejected")return {title:"Rejection confirmed at last check",body:`${value.host} confirmed that this request recorded a rejection for ${entry.candidate?.name||"the joining device"}.`,next:"You can close this view. A later device request has its own review."};
    return {title:"Saved queue check confirmed",body:result.waiting_name?`${result.waiting_name} was waiting when the earlier queue check ran.`:"No device was waiting when the earlier queue check ran.",next:"This is a saved snapshot. Current requests need a new review when phone approvals become available."};
  }
  if(entry.current_result?.state==="in_progress")return {title:"Request still unconfirmed",body:"The network host recorded that the request started. A completed result has not been confirmed.",next:"Keep Connect open on the host and check status again. This will not send the approval or rejection again."};
  if(entry.current_result?.state==="unconfirmed")return {title:"Result still unclear",body:"The network host could not confirm a completed result for this exact saved request.",next:"Keep the original request and check status again. A matching device in your network does not confirm this request."};
  return {title:"Check this device request",body:`Your saved request: ${requestedAction(entry)}. Its result has not been confirmed on this screen.`,next:`Keep Connect open on ${value.host} and choose Check status. This reads the original result without sending the approval or rejection again.`};
}
export function requestsProblem(error:unknown) {
  if(String(error).toLowerCase().includes("busy"))return "This device is busy. Wait a moment, then check status again.";
  return "Could not confirm this saved device request. Keep Connect open on your network host, then check again. The approval or rejection was not resent.";
}
