// What starting a network says about where it runs, when other devices can
// reach it, and keeping a recovery file.

export type Host = "phone" | "computer";

export interface Availability {
  /** Where the network runs and when others can reach it. */
  where: string;
  /** When an always-on computer fits better. */
  alwaysOn: string;
}

export function availability(host: Host): Availability {
  return host === "phone"
    ? {
        where:
          "Your phone runs the network. Your other devices reach it while Connect is open on this phone, and for two minutes after you leave Connect. When Connect is closed, they wait.",
        alwaysOn:
          "Need your devices to reach it at any time? Create the network on a computer you keep on, or a home server, instead.",
      }
    : {
        where:
          "This computer runs the network. Your other devices reach it while this computer is on and Connect is open on it.",
        alwaysOn:
          "Need it at any time, even with this computer off? A home server can run it instead.",
      };
}

/** Where the moment a recovery file was saved is remembered on this device. */
export const RECOVERY_SAVED_KEY = "connect.recovery-saved";

/** The person who runs the network is reminded until a recovery file is saved. */
export function recoveryReminder(owner: boolean, configured: boolean, savedAt: string | null): boolean {
  return owner && configured && !savedAt;
}

/** The Recovery row says whether a file was saved, and when. */
export function recoveryStatus(savedAt: string | null, now = new Date()): string {
  if (!savedAt) return "Not saved yet. Brings this network back on another device";
  const saved = new Date(savedAt);
  if (Number.isNaN(saved.getTime())) return "Brings this network back on another device";
  const days = Math.floor((now.getTime() - saved.getTime()) / 86_400_000);
  const when = days <= 0 ? "today" : days === 1 ? "yesterday" : `${days} days ago`;
  return `Last saved ${when}. Save a new one after big changes`;
}
