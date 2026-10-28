import type { HomeStatus } from "./home-state";
export type ShareKind = "file" | "media" | "folder" | "inbox" | "send" | "service";
export function sharingChoices(status: HomeStatus) {
  const choices: { kind: ShareKind; title: string; description: string }[] = [];
  if (status.can_share) {
    choices.push({kind:"file", title:"File", description:"Keep a read-only copy available to selected devices."});
    choices.push({kind:"media", title:"Photos & videos", description:"Select up to 100 photos or videos from your library or Albums. Share them together with your chosen devices."});
    if (status.can_share_folder) choices.push({kind:"folder", title:"Folder", description:"Share this folder and its subfolders. Files stay on this computer."});
    choices.push({kind:"service", title:"App or service", description:"Share a web app, SSH or TCP service already running on this device. Its own login still applies."});
    choices.push({kind:"inbox", title:"Receive files", description:"Choose who can send files here and where their copies will be saved. Your other files stay private."});
  }
  if (status.configured || status.can_share) choices.push({kind:"send", title:"Send files", description:"Send a file to another device. Your original stays here. Keep Connect open on both devices."});
  return choices;
}
export function sharingDevices(status: HomeStatus) {
  return [...new Map(status.devices.map(device => [device.id, device])).values()];
}

export function receivingChoices(status:HomeStatus) {
  if(!status.can_share_folder) return [{value:"current",label:"In Connect on this device"}];
  const existing=status.spaces.find(s=>s.own&&s.kind==="inbox");
  return [...(existing ? [{value:"current",label:`Keep current location${existing.destination ? ` (${existing.destination})` : ""}`}] : []),
    {value:"default",label:"Downloads → Genesis Mesh (recommended)"}, {value:"choose",label:"Choose another folder…"}];
}
