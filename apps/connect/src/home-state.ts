export interface HomeStatus {
  disconnected: boolean;
  can_leave: boolean;
  leaving: boolean;
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
  can_share_folder?: boolean;
  joining: string | null;
  request: { id: string; name: string; node: string; code: string } | null;
  problem: string | null;
  legacy: boolean;
  connection: ConnectionStatus | null;
  /** Downloads that stopped before they finished, to continue. */
  unfinished: { id: string; name: string; received: number; total: number }[];
}
/** A shared folder: this device's, or another device's shared with it. */
export interface HomeSpace {
  id: string;
  name: string;
  host: string;
  host_id: string;
  own: boolean;
  kind: "folder" | "inbox" | "web" | "ssh" | "tcp";
}
/** Where a shared folder lives, or whose inbox it is, in a few words. */
export function isService(space: HomeSpace) { return ["web", "ssh", "tcp"].includes(space.kind); }
export function spaceSummary(space: HomeSpace) {
  if (isService(space)) return `${space.kind === "web" ? "Web app" : space.kind === "ssh" ? "SSH" : "TCP service"} · ${space.own ? "Shared from this device" : `On ${space.host}`}`;
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
  const units = ["KB", "MB", "GB", "TB", "PB"];
  const power = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length);
  return `${(bytes / 1024 ** power).toFixed(1)} ${units[power - 1]}`;
}
export function friendlyProblem(value: string) {
  if (/policy changed/i.test(value)) return "This policy changed elsewhere. Close and reopen Manage access to load its latest version.";
  if (/custom.*(rule|gate|policy)|policy is disabled|authority before editing/i.test(value)) return "This policy has custom rules that need review at the network authority. Connect has kept them unchanged.";
  if (/network authority cannot be shared|connection cannot be shared again/i.test(value)) return "Choose an application’s port. Connect’s own authority and connection ports cannot be shared.";
  if (/service.*(time limit|expired)|session time limit/i.test(value)) return "This service session ended. Open it again for a new permission check.";
  if (/byte limit reached/i.test(value)) return "This connection reached its policy’s data limit. Ask the sharing device to review Manage access.";
  if (/not enough free storage|check available storage/i.test(value)) return "There isn’t enough free storage to finish this transfer. Free some space on the receiving device or the device preparing the file, then try again.";
  if (/device is disconnected/i.test(value)) return "This device is disconnected. Tap Reconnect in Settings.";
  if (/current transfer|changing networks/i.test(value)) return "Finish or cancel the current transfer, then try again.";
  if (/leaving.*unfinished|finish leaving|could not finish leaving/i.test(value)) return "Leaving hasn’t finished. Unlock this device and retry leaving the network.";
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
