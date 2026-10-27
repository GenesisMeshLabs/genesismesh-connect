import type { HomeSpace, FileEntry } from "./home-state";
export type LibraryFilter = "all" | "remote" | "mine" | "inbox" | "services";
export function visibleSpaces(spaces: HomeSpace[], query: string, filter: LibraryFilter, host: string) {
  const needle = query.trim().toLocaleLowerCase();
  return spaces.filter(s => (!host || s.host_id === host)
    && (filter === "all" || filter === "mine" && s.own || filter === "remote" && !s.own || filter === "inbox" && s.kind === "inbox" || filter === "services" && ["web", "ssh", "tcp"].includes(s.kind))
    && `${s.name} ${s.host}`.toLocaleLowerCase().includes(needle))
    .sort((a,b) => a.name.localeCompare(b.name, undefined, {numeric:true}));
}
export function sortedFiles(files: FileEntry[], sort: string) {
  return [...files].sort((a,b) => {
    if (a.kind !== b.kind) return a.kind === "folder" ? -1 : 1;
    return (sort === "size" ? b.bytes - a.bytes : 0) || a.name.localeCompare(b.name, undefined, {numeric:true});
  });
}
