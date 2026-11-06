# Native client coordinator for pairing Requests

This is a qualification-only native library workflow. It adds no mutation IPC,
frontend signing route, assistant privilege, or production presence provider.
`owner-requests-qualification` is off by default; the existing disabled Android
owner qualification feature forwards it. `UnavailableCommandPresence` refuses.
Only the test fixture implements simulated presence for this slice.

The coordinator supports the existing three actions: inspect the pairing queue,
approve one exact candidate, and reject one exact candidate. It uses the existing
host `Execute` / `Result` exchange and host grant, membership, live-target and
core-readiness checks. It does not replace the host's policy or trust decisions.

## Review and one dispatch

Native code derives the journal path and binding from the selected profile:
protected profile storage ID, network/root pin, authority host, member node and
separate administrative key. The current authenticated enrollment grant must
match the retained request and that binding. The signed command includes the
original grant, exact action/candidate, nonce and expiration.

`review_owner_action` retains that exact command before returning its review.
A second review cannot replace outstanding work or silently sign a replacement.
`submit_owner_action` checks the review digest, current grant and membership,
requires qualified native presence for the exact review, rechecks context/grant,
and atomically reserves before the first transport call. It sends the saved
command once. Production native presence and installed-app gates remain open.

## Interruption and readback

After reservation, failed/lost replies and restart allow `check_owner_action`
only: it asks for the original nonce and digest over the authenticated bridge.
It cannot become another Execute, refresh a command's validity, change its
candidate, issue an invitation, re-enroll or replace identity. Bridge credential
refresh may legitimately close the controller's connection while the host
continues approving the candidate; uncertainty is therefore a normal outcome.

The result view separates the host record observed on this check, its last
observation, and an exact retained terminal outcome. After restart, an old result
is history until readback succeeds. A subsequent membership/grant refresh failure
or grant revocation leaves the operation uncertain and retains prior evidence;
it does not rewrite history as refusal or claim current success.

A queue result is the snapshot produced by its original List command. Checking
that retained result does not re-list the queue. A new approval still requires
its own exact review and the host's current-candidate check.

Matching membership, a paired relationship or an enrollment Active state cannot
complete a command. Missing host records, Started/Unconfirmed results, conflicting
outcomes and unavailable readback stay uncertain. Late/superseded responses cannot
replace a newer check. Expired commands can be checked while their original grant
and retained host record remain valid; missing/pruned records do not permit replay.

## Explicit retirement and storage limits

`archive_owner_action` is a separate explicit local action. It freshly checks the
same operation and current grant before retiring a submitted terminal result.
An expired review that the durable journal proves was never reserved/submitted
may instead be retired locally, without contacting the host or requiring the old
grant to remain active. Its exact digest, original signed command and unsent
state remain in history; no host result is invented. Live unsent reviews, wrong
digests and submitted uncertainty do not qualify for that path. It never
retires submitted uncertainty or creates another command. History remains in the journal;
only a separate subsequent review can begin the next operation.

The bounded private journal holds up to 32 operations and 256 KiB, uses exclusive
native file locking, strict JSON, atomic replacement and sync before dispatch.
An initialization marker fences missing/partial history. Failed persistence
returns no dispatch permission and poisons the in-memory session. Wrong profile,
host, network, member, key, signature, review, reply sequence or clock state refuses
without replacing saved work. No keys are stored in this journal. Its OS-protected
local metadata is not independent audit evidence or cryptographic whole-profile
rollback detection.

## Qualification and remaining gates

The focused workflow enumerates the default-off gate test, journal tests and
`owner_client_commands` disposable embedded-core/QUIC target. That target requires
both qualification features and `CONNECT_FOREGROUND_FIXTURE_PYTHON` pointing to
the existing pinned authority environment. No broad discovery of embedded startup
failure tests is used.

Coverage includes all three actions, exact review/presence refusal, changed live
candidate, lost Execute and Result replies, reopen without another Execute or key,
unrelated local approval reaching matching membership, grant revocation before
and immediately after dispatch, expired grants and fresh core member revocation.
These are host/source checks. App-shell compilation, actual native presence,
physical phone Requests, user acceptance and lifecycle qualification remain open.

The independent phone-local authority remains a requirement. This coordinator
uses the same authority-host boundary; it introduces no mandatory Windows,
NAS/server or hosted service. The membership inspector and pairing-completion
recovery are separate and unchanged.

## Read-only saved device-request view

Devices now has a **View saved device request** entry. The view explains the
original action, the last confirmed result and a safe next step. **Check status**
reads only the original operation; it cannot approve/reject again, sign a new
command, retire work or replace device identity. Joining permissions has its own
next destination. Original review codes and timestamps are kept in details.

The app receives a small native projection: an internal matching reference,
context digest, human action/candidate, current host-record observation and
clearly separate retained history. No keys, signed commands, grants, paths or
endpoint details cross this display IPC. Local inspection does not initialize
an empty command workflow or administrative key. Default builds report the
capability unavailable before opening qualified command/key state.

A confirmed queue result is described as a saved snapshot. Earlier success stays
history on reopen, interruption, host/grant failure or an unconfirmed readback.
Responses for a different profile/host/key context, original operation, candidate
or code cannot replace the current screen. Close, Escape, navigation and network
changes fence abandoned loads and checks.

Only two fixed, no-input read-only handlers are registered:
`client_requests_status` and `client_requests_check`. There is no new mutation,
signing, presence-provider, Execute or archive IPC. Sending device approvals
remains gated. Source/browser fixtures exercise the actual component against
explicit simulated native replies; separate disposable embedded-core/QUIC
fixtures qualify the native projection/readback. Neither demonstrates installed
Tauri app, native device authentication or physical phone acceptance.

See [display validation](evidence/requests-display-2026-11-06.json). The focused
workflow selects these exact source tests and browser files, without dispatching
broad or excluded startup-failure qualification.
