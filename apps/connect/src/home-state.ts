export interface HomeStatus {
  owner: boolean;
  configured: boolean;
  network: string | null;
  peer: string | null;
  devices: {
    id: string;
    name: string;
    selected: boolean;
    authority_connection: boolean;
    member: boolean;
  }[];
  selected_device: string | null;
  ready: boolean;
  sharing: string | null;
  spaces: HomeSpace[];
  can_share: boolean;
  joining: string | null;
  request: { id: string; name: string; node: string; code: string } | null;
  problem: string | null;
  legacy: boolean;
  connection: ConnectionStatus | null;
}
/** A shared folder: this device's, or another device's shared with it. */
export interface HomeSpace {
  id: string;
  name: string;
  host: string;
  host_id: string;
  own: boolean;
  kind: "folder" | "inbox";
}
/** Where a shared folder lives, or whose inbox it is, in a few words. */
export function spaceSummary(space: HomeSpace) {
  if (space.kind === "inbox")
    return space.own ? "Receiving files from your devices" : `Send files to ${space.host}`;
  return space.own ? "Shared from this device · read-only" : `On ${space.host}`;
}
/** A send's progress in a few words. */
export function sendSummary(progress: { state: string; sent: number; total: number; saved_as: string | null }) {
  if (progress.state === "checking") return "Preparing…";
  if (progress.state === "complete") return progress.saved_as ? `Sent · saved as ${progress.saved_as}` : "Sent";
  if (progress.state === "canceled") return "Sending canceled";
  return `${formatBytes(progress.sent)} of ${formatBytes(progress.total)}`;
}
/** What the empty Files view suggests next. */
export function filesEmptyText(status: HomeStatus) {
  if (!status.can_share) return "Nothing is shared with this device yet.";
  return status.devices.length
    ? "Share a folder to make it available on your other devices."
    : "Add a device to start sharing.";
}
export type Connectivity = "public_relays" | "local_network";
export interface ConnectionStatus {
  network: Connectivity;
  own: Connectivity | null;
  effective: Connectivity;
  network_computer: boolean;
  guided: boolean;
}
/** One plain sentence for Settings: what this device uses, and who chose it. */
export function connectionSummary(connection: ConnectionStatus | null) {
  if (!connection) return "";
  if (connection.effective === "public_relays")
    return "Public relays: your devices reach each other from anywhere.";
  if (connection.network === "public_relays")
    return "This device connects only on the local network. Your network also allows public relays.";
  return connection.network_computer
    ? "Private: your devices connect only on this local network."
    : "Private: your network computer keeps every device on the local network.";
}
export interface FileEntry {
  name: string;
  kind: "file" | "folder";
  bytes: number;
  version: string;
}
export interface FilePage {
  collection_id: string;
  directory: string[];
  files: FileEntry[];
  next: string | null;
}
export function folderCrumbs(directory: string[]) {
  return [{ name: "Shared folder", directory: [] as string[] },
    ...directory.map((name, index) => ({ name, directory: directory.slice(0, index + 1) }))];
}
export function primaryScreen(status: HomeStatus) {
  if (status.joining) return "joining";
  if (status.configured) return "workspace";
  return "welcome";
}
export function filterFiles(files: FileEntry[], query: string) {
  const text = query.trim().toLocaleLowerCase();
  return files.filter((file) => file.name.toLocaleLowerCase().includes(text));
}
export function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
}
export function friendlyProblem(value: string) {
  if (/Share the folder again|larger files/i.test(value)) return "Share this folder again on your computer to allow larger files.";
  // A device that shares no folder offers no file protocols at all.
  if (/support any known protocol/i.test(value)) return "This device isn’t sharing anything with you yet.";
  if (/authority unavailable|connection is suspended/i.test(value)) return "Your network computer isn’t ready. Keep Connect open there and try again.";
  if (/timed out|timeout|connection lost|closed by peer|did not respond/i.test(value))
    return "Couldn’t reach your other device. Keep Connect open on both devices and try again.";
  if (/file changed|version changed/i.test(value)) return "This file changed. Refresh the list and try again.";
  if (/permission|not allowed|denied/i.test(value)) return "Access wasn’t allowed. Check folder sharing on your computer.";
  if (/another.*running|current download|too many/i.test(value)) return "Please finish the current operation, then try again.";
  if (/join your network|add your other device|set up this computer/i.test(value)) return "Connect your devices first.";
  return "Couldn’t complete this. Please try again.";
}
