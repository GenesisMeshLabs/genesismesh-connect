// What the screen says while a read waits for the device that has the files,
// as while that device restarts. The wait lasts at most two minutes.

/** Quick answers show nothing extra; a wait is explained after this long. */
export const EXPLAIN_AFTER_MS = 2500;
/** Must match the core's budget for asking again (`ASK_AGAIN_FOR`). */
export const WAIT_LIMIT_MS = 120_000;
/** What the core says when the person stopped waiting (`waits::STOPPED`). */
export const STOPPED = "Stopped waiting. Nothing was changed.";

/** Minutes and seconds, as 0:07 or 1:32. */
export function elapsed(ms: number): string {
  const seconds = Math.max(0, Math.floor(ms / 1000));
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
}

export function waitTitle(device?: string | null): string {
  const name = device?.trim();
  return name ? `Waiting for ${name}` : "Waiting for your network device";
}

/** How long it has waited, what may be happening, and when it stops. */
export function waitDetail(ms: number): string {
  const left = WAIT_LIMIT_MS - ms;
  const why = left > 60_000
    ? "It may be restarting, or Connect may be closed on it."
    : left > 0
      ? "Still trying. Keep Connect open on that device."
      : "Finishing the last try.";
  return `${elapsed(ms)} · ${why}`;
}

export function stoppedWaiting(error: unknown): boolean {
  return String(error).includes(STOPPED);
}
