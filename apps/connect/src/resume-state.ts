// Where the person was, so returning to Connect, even after Android ended it in
// the background, feels like resuming rather than starting over.

export type View = "files" | "devices" | "activity" | "settings";
const VIEWS: readonly View[] = ["files", "devices", "activity", "settings"];

export interface Place {
  view: View;
  /** The Space that was open, if any. */
  space: string | null;
  /** The folder inside it. */
  path: string[];
  /** When this was remembered, in milliseconds. */
  at: number;
}

export const PLACE_KEY = "connect.place";
/** After this long, Connect opens at its usual start instead. */
export const RESUME_FOR_MS = 24 * 60 * 60 * 1000;
const MAX_DEPTH = 16;

export function place(view: View, space: string | null, path: string[], now = Date.now()): Place {
  return { view, space, path: space ? path : [], at: now };
}

/** A remembered place, or null when it is missing, malformed or too old. */
export function readPlace(saved: string | null, now = Date.now()): Place | null {
  if (!saved) return null;
  let value: unknown;
  try {
    value = JSON.parse(saved);
  } catch {
    return null;
  }
  if (typeof value !== "object" || value === null) return null;
  const { view, space, path, at } = value as Record<string, unknown>;
  if (!VIEWS.includes(view as View)) return null;
  if (space !== null && typeof space !== "string") return null;
  if (!Array.isArray(path) || path.length > MAX_DEPTH || !path.every((part) => typeof part === "string" && part.length > 0))
    return null;
  if (typeof at !== "number" || now - at > RESUME_FOR_MS || at > now + 60_000) return null;
  return { view: view as View, space: space as string | null, path: space ? (path as string[]) : [], at };
}

/**
 * What to reopen given the Spaces this device can see now: the same view, and
 * the same Space and folder only while that Space is still shared with it.
 */
export function resumeTo(saved: Place | null, spaces: readonly { id: string }[]): Place | null {
  if (!saved) return null;
  if (saved.space && !spaces.some((space) => space.id === saved.space))
    return { ...saved, space: null, path: [] };
  return saved;
}
