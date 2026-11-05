# Review and recover an access change

The first typed workflow upgrades **Shared → Manage access**. Choose devices,
expiry and limits, select **Review change**, inspect the affected item and
devices, then **Confirm access change**. **Change choices** cancels the pending
review without submitting it. This is a local explanation, not a core simulation
or a permission decision. Core validates the actual mutation.

The native shell stores `connect.access.update.v1` with a strict versioned Rust
schema. Its ID, pinned root/network, acting device, network-computer audience,
resource ID/name, previous policy, exact proposed settings and five-minute
expiry are bound by the SDK canonical digest. Confirmation supplies only the
stored ID and digest. Choices cannot be swapped into the commit call. The
previous direct frontend update command is no longer registered.

Immediately before submission, native code refreshes trust, resolves the current
device and saved resource, checks recipients and re-reads the policy. A changed
context, name, version, policy, digest, expired review or repeated submission is
refused. Core still checks resource ownership, versions, limits and gate
semantics. Ordinary membership does not acquire owner administration powers.

## Unconfirmed changes

The private device-local journal persists dispatch **before** invoking the
existing adapter. After an application crash, an unfinished dispatch becomes
**unknown**, retaining the same intent and identity. It is never automatically
replayed. Reopening Manage access finds that state. **Check status** reads the
current authority settings and may refresh the local sharing configuration; it
does not reissue the policy mutation.

Three facts are kept separately:

- A successful adapter reply records **core accepted**. A missing reply leaves
  authorization unknown.
- An exact matching next policy version records **state observed**. That
  observation cannot identify which request produced it.
- Updating this device's saved share is separate from authority readback. It
  does not establish that a remote recipient accessed the resource successfully.

Different later state is a conflict requiring fresh settings and review.
Unchanged state after an uncertain submission remains unknown: it cannot rule
out a pending action. Another change to that resource is blocked until the
uncertainty is resolved. There is deliberately no generic Retry or “mark failed”
button. A permanently ambiguous/partially committed core operation still needs
operator investigation; automatic attribution or safe retry requires a core
operation-specific status/idempotency contract.

The journal is strict bounded JSON, exclusively locked, atomically replaced and
flushed. Corruption, missing previously initialized history, lock or write failure
refuses dispatch. On Unix its files use mode 0600. It stores policy metadata,
not private keys, invitations, passwords, file contents or signed core receipts.
The app container and host OS are the local security boundary; this is not a
tamper-evident evidence ledger. Settled history is durably archived before active
compaction; unresolved dispatches remain active. A user-facing archive/evidence
browser remains future Activity work.

## Runtime prerequisites and limits

The local inherited-pipe adapter has a fixed `capabilities` operation. It checks
the installed release against the single packaging pin, names its network and
advertises only this implemented access adapter. Rust verifies those fields
before local mutation. This is not remote-owner enrollment, general feature-flag
discovery or a list of core permissions.

Remote resource hosts now use [resource-scoped prerequisite discovery](resource-prerequisites.md)
over the authenticated Iroh bridge, with host-only authority checks. The response
binds root/network, actor, item, actual managed release, deployment profile,
policy version and supported resource operations. Native review/commit recheck
these requirements; a cached response is not a grant. Full discovery across
arbitrary external deployments and general owner/agent roles remains CONNECT-04 work.

Connect checks stale state immediately before dispatch and uses the existing
adapter's version refusal. This is **not** an atomic cross-process compare-and-swap
against concurrent independent administrator writes: the adapter performs a
multi-step core mutation. General conflict fencing and exactly-once execution
need operation-specific core support. No core protocol or root custody changed.

The [typed resource registry](operation-contract.md) includes inspection, update
and prerequisite discovery. It does not complete the general core registry,
visual policy editor, assisted workflow, independent approval, remote-owner
Requests protocol, or enrollment/recovery journal.

## Verification record — 5 November 2026

Automated checks use disposable identities and networks:

- Rust journal tests cover wrong actor/root/audience, altered digest/policy,
  expiry/clock rollback, replay, corruption, missing history, cancellation,
  exclusive writer, persistence failure, crash recovery and archive retention.
- A real released authority test verifies preview has no policy effect, an
  actual commit survives a lost application reply/restart, recovery does not
  create an extra policy version, and stale/unauthorized writes are refused.
- Existing 14 same-host real-authority/QUIC tests pass, including resource
  denial, nested/large files, remote hosts and service revocation.
- Linux native-shell checking and Clippy complete. The existing Rust 1.99
  deprecation warning in `session/sharing/service.rs` remains; this is not a
  passing warnings-as-errors gate.
- A freshly packaged standalone Linux authority passes network creation,
  enrollment, restart/rebind and recovery-file restoration tests. Its readiness
  check reads the bundled single-source release pin, not a developer source file.
- Frontend tests, TypeScript and Vite production compilation pass. A Chrome
  **synthetic mocked-IPC preview** exercised recipient removal, exact review,
  confirmation, unknown-state blocking and status reconciliation. It is not
  native end-to-end execution. Browser control timed out during phone-width
  verification; that responsive gate remains unperformed.

No new Windows executable or mobile package was installed. The previously
reported Windows Application Control compilation block is unresolved. Mac,
iPhone, Android, real phone-width rendering and physical lifecycle/novice
acceptance have not been established by this batch.

Repeat the journal checks with `cargo test -p connect-core --test access_workflow
--locked`. Run the real adapter check with a matching `CONNECT_NA_PYTHON` and a
disposable native secret store:

```sh
CONNECT_NA_PYTHON=/absolute/path/to/python \
bash scripts/verify-linux-store.sh test -p connect-core \
  --test access_workflow_authority --locked -- --ignored --nocapture
```

The Windows `scripts/verify.ps1` gate also includes this real-authority test.
