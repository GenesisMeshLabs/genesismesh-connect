import type { HomeStatus } from "./home-state";
export type ShareKind = "file" | "media" | "folder" | "inbox" | "send" | "service";
export function sharingChoices(status: HomeStatus) {
  const choices: { kind: ShareKind; title: string; description: string }[] = [];
  if (status.can_share) {
    choices.push({kind:"file", title:"File", description:"Keep a read-only copy available to selected devices."});
    choices.push({kind:"media", title:"Photo or video", description:"Choose from your device. Selected devices can view or save a copy."});
    if (status.can_share_folder) choices.push({kind:"folder", title:"Folder", description:"Share this folder and its subfolders. Files stay on this computer."});
    choices.push({kind:"service", title:"App or service", description:"Share a web app, SSH or TCP service already running on this device. Its own login still applies."});
    choices.push({kind:"inbox", title:"Receive files", description:"Let selected devices send files to an inbox on this device."});
  }
  if (status.spaces.some(s => !s.own && s.kind === "inbox")) choices.push({kind:"send", title:"Send a copy", description:"Deliver one file to another device's inbox."});
  return choices;
}
export function sharingDevices(status: HomeStatus) {
  return [...new Map(status.devices.map(device => [device.id, device])).values()];
}
