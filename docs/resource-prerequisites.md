# Resource access prerequisites

Opening Manage access checks the network computer through a fixed
`connect.resource.capabilities.v1` operation. It uses the same inherited local
pipe on the network computer and mutually authenticated Iroh bridge on a remote
sharing device. There is no caller-provided host identity, authority URL or
administrator request.

The authority adapter verifies that the current resource registry names the
authenticated device as host and that its policy is active and editable. A
recipient of a folder is not its host. Unknown, stopped or somebody else's
resources are refused. The bridge also requires a current credential and saved
device; refused unsaved callers never reach the owner runtime.

The typed reply names the pinned root/network, acting device, exact resource,
current policy version, known deployment profile and fixed operation IDs. Rust
rejects a wrong scope, unsupported schema, incompatible managed release,
duplicate/unknown operations or missing operation support. New clients do not
assume feature support when an older host cannot answer discovery. Keep that
computer awake and update Connect there before using the new workflow.

The profile determines what this **preview implementation can establish**:

| Profile | What is checked | User experience |
| --- | --- | --- |
| Connect managed | The authority is in this adapter's process; its installed release matches the packaging pin, policy enforcement is required, and its configured operator tier is privileged | Inspection and access changes are available, with fresh review and core authorization |
| Connect restricted | The same managed process is known, but required enforcement or operator tier is missing | Current settings are shown read-only, with a setup explanation |
| External unverified | A separate authority was attached; the local adapter's package metadata cannot establish that other process's release or flags | Current settings are shown read-only; no authority version is invented |

An unverified external profile does not establish that the authority lacks the
feature. It identifies a missing verification contract. Supporting general
attached deployments requires authenticated core version/feature/operator
discovery; Connect does not infer it from a successful read or `/health`.
General remote owner administration remains a different protocol and enrollment.

Before review and again before commit, native code obtains fresh metadata,
checks update support and matches its policy version to the current policy
readback. The existing core validates every actual write. Discovery is neither a
bearer capability nor a signed portable artifact. It does not approve a future
action, expose operator credentials, add independent approval or replace core
permissions. The existing version/cross-process concurrency limitations in the
[access workflow](access-workflow.md) still apply.

Existing wire operations remain for older clients. Adding discovery does not
change their membership privileges or bypass their core policy checks. The
current guided client's stricter prerequisite behavior does require updating its
network-computer adapter before editing access.

## Verification — 5 November 2026

Disposable real-core and same-host QUIC checks verify successful host discovery,
recipient/wrong-root/unsaved-device refusal, no policy version change during
discovery, and new versions after a real access update. Python tests verify
restricted flags/operator tiers, externally unverified metadata, stopped shares
and no policy effect. Strict model tests reject scope/version/profile/operation
tampering. Standalone Linux bundle checks exercise this fixed operation without
developer source files alongside creation, restart and recovery smoke tests.

Chrome **mocked native IPC** checks exercised read-only guidance, disabled
controls and the editable review/confirmation flow at desktop and 390×844 phone
widths. These are UI checks, separate from native execution and physical iPhone/
Android acceptance. No installed user app or network was changed. Windows native
compilation still has the previously reported Application Control blocker;
Mac/mobile packages and physical lifecycle checks remain unperformed here.
