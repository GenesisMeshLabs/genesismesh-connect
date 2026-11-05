# Local access history

Open **Activity** from normal navigation. **All changes** includes reviews,
cancelled changes, checked results and settled archives. **Needs attention**
focuses on unconfirmed or conflicting dispatched changes. Open **View record**
for the reviewed devices, removed recipients, limits and observed policy version.
Exact JSON stays collapsed by default. History belongs to this device’s current
network and identity; it is cleared from the screen when that scope changes.

**Check status** is a read-only reconciliation through the existing access
workflow. Native checks resolve the current root, actor, resource host and owned
item again. Older archives, previous hosts, stopped items and disconnected
devices cannot use that action. Matching state after a lost reply does not prove
which request applied it, and never triggers an automatic resend.

**Save record** reads the scoped record again and asks for a native destination.
Desktop export atomically writes JSON to the chosen path. Mobile export places
JSON in Connect’s private export cache and opens the OS share sheet; opening that
sheet is not confirmation of an external save. The caller supplies only a record
ID, never a path. Exported records are not imports or execution approvals.

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

Qualification for this slice includes Linux core/native-shell checks, real-core
lost-response/restart readback, packaged Linux authority checks and frontend
state tests. Chrome mocked-IPC checks exercised filtering, details, readback,
export feedback, offline/partial history and mismatched-scope clearing at desktop
and 390×844 phone widths. This is not an installed Windows/mobile acceptance
test. Windows Application Control remains an unresolved native-build gate;
Mac/iOS/Android builds, OS pickers/share sheets and physical lifecycle testing
remain unperformed for this slice. Existing Rust 1.99 deprecation warnings remain.
