import type { HomeStatus } from "./home-state";

export type EverydayView = "files" | "devices" | "settings";
export function helpStatus(status:HomeStatus|null) {
  if(!status)return "Checking this device";
  if(status.leaving)return "Cleanup needs attention";
  if(!status.configured)return "Setup needed";
  if(status.disconnected)return "Disconnected";
  if(status.problem)return "Needs attention";
  return "Joined network";
}
export function advancedGuidance(status: HomeStatus | null) {
  const selected=status?.devices.find(d=>d.id===status.selected_device);
  const canCheck=!!status?.configured&&!status.disconnected&&!status.leaving&&!!selected;
  if(!status) return {title:"Getting your device status",detail:"You can read the guides while Connect checks this device.",action:"Open Connect",view:"settings" as EverydayView,canCheck,selected:"Checking saved devices…",checkHint:"Checking this device…"};
  const checkHint=status.leaving?"Finish leaving this network before running a check.":!status.configured?"Finish creating or joining a network first.":status.disconnected?"Reconnect in Settings before running this check.":!status.devices.length?"Add another device from your network computer.":"Choose a saved device above.";
  const base={canCheck,selected:selected?.name||"No saved device selected",checkHint};
  if(status.leaving)return {...base,title:"Finish leaving this network",detail:"Return to Connect and retry the unfinished cleanup before creating or joining a network.",action:"Finish leaving",view:"settings" as EverydayView};
  if(!status.configured) return {...base,title:"Start with the everyday setup",detail:"Create a network or join with an invitation. Connect handles device keys during that setup.",action:"Open setup",view:"devices" as EverydayView};
  if(status.disconnected) return {...base,title:"This device is disconnected",detail:"Reconnect in Settings when you want to use your network again. Your setup is saved.",action:"Open connection settings",view:"settings" as EverydayView};
  if(status.problem) return {...base,title:"A connection needs attention",detail:"Start with Connection help below. It guides you through the saved-device check before any manual setup.",action:"Review your devices",view:"devices" as EverydayView};
  if(!status.devices.length) return {...base,title:"Add your next device",detail:"Use an invitation to bring another device onto this network, then choose what to share.",action:"Open Devices",view:"devices" as EverydayView};
  return {...base,title:"Choose what you need help with",detail:"Check a saved connection, understand permissions, or review recent technical activity.",action:"Open Shared",view:"files" as EverydayView};
}

export function connectionFailure(error: string) {
  if(/timed? out|timeout|deadline/i.test(error)) return {
    title:"The other device did not reply in time",
    detail:"Keep both apps open, check that the network computer is awake, and try again. File and service permissions are checked separately.",
  };
  if(/connection refused|os error (10061|111|61)\b/i.test(error)) return {
    title:"Connect could not open a connection",
    detail:"Keep Connect open on the other device and the network computer, then try again.",
  };
  if(/expired.*(certificate|credential)|(certificate|credential).*expired/i.test(error)) return {
    title:"The device credential needs an update",
    detail:"Keep the network computer open and try again so Connect can refresh this device. Ask the network owner for help if renewal keeps failing.",
  };
  if(/refused|revoked|denied|invalid.*certificate|identity.*fail/i.test(error)) return {
    title:"The connection was refused",
    detail:"Ask your network owner to review this device. Technical details below show why the request could not proceed.",
  };
  return {title:"The connection could not be confirmed",detail:"Check the saved device and keep both apps open, then try again. Open technical details if you need to ask for help."};
}
