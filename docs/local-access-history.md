# Local access history

`access_workflow::history` reads the current access journal and settled archives.
It is device-local workflow metadata, **not signed core evidence**, a network-wide
ledger or proof that a file/service was used. Reading it makes no authority call
and never submits an operation. Opening an interrupted active journal retains the
existing conservative submitted-to-unknown recovery behavior.

The native caller supplies the current pinned network and device identity; input
queries contain only a filter, bounded page size and cursor. The same network
name under a different root, or another device identity, does not expose records.
A cursor is bound to that scope and filter. Stable creation-time/ID pagination
does not repeat newer entries inserted before the next page. This is not a sealed
point-in-time snapshot of independently changing local history.

Active records take precedence over an archive duplicate left by interrupted
compaction. Older conflicting archive identities or unreadable, unsupported,
oversized and linked files produce an explicit incomplete-history result while
preserving original data. A request scans at most 256 archive directory entries
and 64 MiB of archive bytes, in addition to the bounded active journal. Reaching
a limit never turns into a claim that the returned set is the entire history.

“Needs attention” selects the latest dispatched unresolved/conflicting change per
item and network-computer audience. A later checked change supersedes an old
conflict in that filter without deleting it. Current host, shared-item presence,
connection status and archive status determine whether **Check status** is
eligible. Archived records are descriptive history, never a restored approval or
an automatically replayable request.

Record exports retain the original intent/digest and observations with
`evidence_class: unsigned_local_workflow_metadata` and `signed: false`. The digest
checks the intent representation; anyone able to rewrite this metadata can also
recompute it. It is not an authority signature or an independently verifiable
audit pack. No imported record enters the execution path.

The OS app container is the local privacy boundary. Network recovery files do not
currently include this journal or its archives; local history does not imply
network-wide continuity or reconstruction after losing the device.

Automated tests cover root/actor isolation, cursor and filter mismatch, concurrent
insertion, old conflicts, unknown recovery hints, duplicate archive copies,
corruption preservation, scan limits, link refusal and unsigned exports. Existing
real-compaction tests also read archived records back through this API.
